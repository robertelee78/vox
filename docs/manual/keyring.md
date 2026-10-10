# Identity and keyring

This page shows how to manage your nodes and decide whom each one trusts. The examples act as
`robertgpt`, whose keyring holds `ann`. With more than one node attached, add `--node robertgpt`.

## Your nodes

A node is one identity: its own keys, rooms, keyring and services. Give each person and each agent
a node of its own. Never share one between a person and an agent.

| To | Run |
|---|---|
| Make a node | `vox node create robertgpt` |
| List the nodes on this machine | `vox node list` |
| Attach a node | `vox node attach robertgpt` |
| Detach a node | `vox node detach robertgpt` |
| Stop Vox attaching it by itself | `vox node forget-passphrase robertgpt` |
| Rename it on this machine | `vox node rename robertgpt robert-laptop` |
| Sign it out | `vox node signout robertgpt` |

`vox node create` asks for the identity passphrase twice, or reads it from `--passphrase-file`.
Leave it empty to make a node with none: Vox then says that the node's key is kept unencrypted, so
anyone who can read its data folder can act as it. There is no command to change a passphrase.

At a terminal, `vox node create` also attaches the node. Run by a script, it only makes it. There
is no backup of a node: its keys never leave the machine. If the machine is lost, make a new node,
and ask everyone who trusted the old one to remove it and trust the new one.

An attached node runs in the daemon until you detach it. Attaching remembers it: Vox stores the
passphrase in the Keychain (nothing, for a node with none), and the daemon attaches the node again
whenever it starts, after an update or a reboot too. Anyone who can unlock this Mac's login
keychain can then attach it. To attach without remembering, add `--no-remember`. On Linux there is
no Keychain, so keep the node with a passphrase file instead:
`vox node attach robertgpt --keep --passphrase-file ~/.vox-robertgpt-passphrase`.

`vox node list` shows each node as `attached` or `detached`, with its fingerprint, and `(kept)` for
one the daemon attaches by itself.

`vox node detach` closes the node's connections, stops its services and wipes its keys from
memory. It also forgets the node: the daemon stops attaching it by itself, and its passphrase
leaves the Keychain. Its rooms and keyring stay on disk.

`vox node forget-passphrase` forgets the node in the same way but leaves it attached.

`vox node rename` keeps the node's identity, so its fingerprint stays the same. It moves the name
everywhere this machine holds it: the node's directory, its remembered passphrase, the harnesses
wired to it, and the app's choice of node. If a keyring on this machine names the node, the
command prints the `vox trust rename` that updates it.

`vox node signout` detaches the node, forgets it, and makes the app forget it chose it. Its rooms
and messages stay. `vox node attach` brings it back.

## When the passphrase is asked for

Vox asks for the identity passphrase in two cases only: when you attach the node, and when you
change its keyring with `vox trust add`, `remove`, `rename`, `drive` or `read`. Posting, reading,
sharing, and a room's name or retention never ask.

A passphrase typed for a keyring change opens the keyring for 30 minutes. Further changes in that
time do not ask. A passphrase typed to attach the node does not open it. While the keyring is
open, any program running as you, an agent included, can change it. `vox status` shows the state
on its second line: `keyring asks for the passphrase`, or `keyring open 30m` with the minutes left.

A keyring change takes the passphrase only from a terminal. It never reads a file or
`VOX_IDENTITY_PASSPHRASE`. Without a terminal, the change is refused and Vox prints the command to
run in one:

```text
vox: changing who you trust needs your identity passphrase: it was not entered for a keyring change in the last 30 minutes
       it is typed at a terminal, and taken from nothing else (not VOX_IDENTITY_PASSPHRASE, not a file). Run it in a terminal: vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --name ann
```

## An agent's node

An agent's node follows the same rules. You, the operator, type its passphrase in a terminal
outside the agent's session:

```sh
vox node attach claude-mac
vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --name ann --node claude-mac
```

The agent's hook never attaches the node and never takes a passphrase. While the node is
detached, the agent is told so, with the command for you:

```text
Vox could not read your rooms this turn: node claude-mac is not attached, and a hook never attaches it. Ask the operator to run, in a terminal outside this session: vox node attach claude-mac
```

## Compare before trusting

`vox id` prints your node's whole fingerprint. Get the other person's whole fingerprint through a
way you already trust, such as in person or a call, and compare every character. A short prefix is
not proof. A different key is a different node: if someone replaces their machine, compare the new
fingerprint before you trust it, whatever name it claims.

## Offers: nodes waiting for your trust

When a node joins a room after yours and is not in your keyring, your node offers it to you. So
does a node that trusts you. An offer waits until you accept it, dismiss it, or the node leaves.
Nothing is posted to the room either way. To list offers, run:

```sh
vox trust offers
```

```text
◣◣◢◢◣◣◥◥◤◤  f7l2 q44g 56mz d62n svck
◣◣◢◢◣◣◣◣◣◣  7mof ibuj 4l57 uchh i446
◥◥◥◥◣◣◣◣◣◣  s32w 3cg5 arrq
◤◤◤◤◣◣◤◤◥◥
◥◥◥◥◥◥◢◢◢◢
  f7l2q44g56mzd62nsvck7mofib (not in keyring) joined. No one you trust trusts it yet.
  in "family"
  accept (read): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt
  accept (read + drive): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt --drive
  dismiss: vox trust dismiss f7l2q44g56mz --node robertgpt
```

Each offer shows the fingerprint beside a picture drawn from it, for a quick visual check, why it is offered (`joined`, `trusts you`, or
both), which of the nodes you trust already trust it, and the rooms you share. Check the
fingerprint, then:

- To accept, copy the `accept (read)` command and run it at a terminal. Vox asks for your name for
  the node and your identity passphrase. Use `accept (read + drive)` only for a node you let drive
  your agents' Sessions.
- To dismiss, run the `dismiss` command. The node is not told. It is offered again only if it
  leaves and joins again.

When you remove a node from your keyring, its offer is dismissed too.

An agent sees the offers for its node in its own turn, with the same commands for you to run
outside its session. Only you accept one.

## Trust a node

With the fingerprint compared, run:

```sh
vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --name ann
vox trust list
```

The name is yours alone. Without `--name`, Vox asks for one at a terminal. Before and after it
asks for the passphrase, Vox says what the trust grants:

```text
vox: trusting f7l2q44g56mzd62nsvck7mofib as "ann": read
     it may now read what you write in "family" — now and later
     and you read what it writes, once it trusts you too
     and reach every service you bind to a room you are both in
     `vox trust remove` undoes it and changes the lock everywhere
```

Trust covers every room you share with the node, including rooms you share later. `--history full`
also releases your own earlier messages that you still hold a key for. The default, `now`, releases
only what you write from now on. Neither releases anyone else's messages.

Trusting sends the node your key for each room you share. The key is locked to keys the other
node publishes in the room. If those have not reached your node yet, your key waits and goes when
they arrive. The daemon's log says so once.

## What a keyring entry grants: read, or read + drive

Each entry grants **read**: the node reads what you write and reaches your services. Or it grants
**read + drive**: it also drives your node's Sessions, typing into them, interrupting, approving
and answering. `vox trust list` shows which, after the name:

```text
f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq  ann  read + drive
```

```sh
vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --name ann --drive
vox trust drive f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq
vox trust read f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq
```

`vox trust add --drive` grants read + drive from the start. `vox trust drive` adds drive to a node
you trust. `vox trust read` takes drive back: the node keeps what it already read inside your
Sessions and reads nothing written there afterwards.

## Rename a node in your keyring

```sh
vox trust rename f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq annie
```

Vox prints the new name and the addresses its services now have, such as
`<service>.annie.<room>.vox`. Renaming grants and removes nothing. To change a name, rename. Do
not remove and add again, because removing rotates keys.

## Remove a node from your keyring

Removing a node withdraws its reading and its service access in every room you share. It keeps
what it already read.

```sh
vox trust remove f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq
vox trust list
```

Before it acts, Vox says what the node is to lose and which of its live sessions into your
services it is to cut. Afterwards it reports:

```text
vox: removed f7l2q44g56mzd62nsvck7mofib from your keyring
     your sender key is rotated and everyone still trusted is re-keyed
     cut: none was open
     your sessions into its services are untouched
```

## Trust from the TUI

In the terminal interface, the members pane shows trust in glyphs and words:

- `⇄ alice`, bold, `trusted both ways`;
- `→ dave`, bold, `waiting for the other side`: you trust it, it does not trust you yet;
- `·` and the start of a fingerprint, `not in keyring: trust to read each other`.

Under a node in your keyring, a line says `read` or `read + drive`. Select a member to see its card:
the whole fingerprint in groups beside its picture.

To trust a member, press `t` on it, or type `:trust` and the start of its fingerprint. The TUI asks
for the fingerprint as they gave it to you (spaces, dashes and case do not count), your name for
them, and your identity passphrase. If the fingerprint you paste is not this node's, nothing is
added and the TUI shows both.

Offers come first under **needs you** on the room list. Select one: Enter trusts it (`r` or Enter
for read, `d` for read + drive), and `x` dismisses it. `k` on the room list shows your keyring.
