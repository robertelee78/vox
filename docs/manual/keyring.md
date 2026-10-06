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

`node create` writes the identity and prints its fingerprint; it attaches nothing. It also says
`there is no backup of a node: if this machine is lost, so is this node; make a new one, and ask
everyone who trusts this one to untrust it and trust the new one`. That is the whole recovery
plan: a node's keys never leave its machine, so no copy of them exists to restore. `node attach`
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
Vox states this before it acts and again after, naming the rooms you share:

```text
vox: about to trust 3jnhi236j2ktt7zgzs4iixoy7s as "ann"
     it is to read what you write in "family", and in any room you share with it later
     and to reach your services in a room you share, once you offer one
vox: trusting 3jnhi236j2ktt7zgzs4iixoy7s as "ann"
     it may now read what you write in "family" — now and later
     and you read what it writes, once it trusts you too
     and reach every service you bind to a room you are both in
```

It is not just permission for the currently open room or one
file. The other node makes its own independent decision to trust you. For a conversation,
confirm a message can be read in each direction.

`--history` chooses what of **your own** earlier messages the trusted node can read: `now`, the
default, releases what you write from this approval onward; `full` also releases everything you
still hold a key for. It never releases anyone else's messages.

A keyring change (add, rename, remove) asks for the identity passphrase unless you typed it for a
keyring change in the last 30 minutes; attaching the node does not count. It is typed at a
terminal and taken from nothing else: `--identity-passphrase`, `--identity-passphrase-file` and
`VOX_IDENTITY_PASSPHRASE` are not read for it. Without a terminal the change is refused, with the
command to run in one.

To see where you are in that window, run `vox status`. Its second line is `keyring open 30m`, with
the minutes left, while a keyring change goes through without the passphrase. It reads `keyring
asks for the passphrase` once the window has closed. The TUI's status bar shows the same words
while a node is attached.

## Rename a node in your keyring

```sh
vox trust rename FULL_FINGERPRINT annie
```

Vox confirms the new name and the service address it gives, for example `its services are
reachable as <service>.annie.<room>.vox`. Renaming grants and removes nothing; only a node you
already trust can be renamed. Do not remove and re-add a trusted node to change its name:
removal has real access and key-rotation consequences.

## Understand the member pane

The TUI shows trust by glyph, weight and words, never by colour alone:

- `⇄ alice`, bold: alice is in your keyring and her node trusts yours too;
- `→ dave`, bold: dave is in your keyring, and his node does not trust yours;
- `· ` and 26 characters of a fingerprint, plain: a node not in your keyring.

Where two nodes in your keyring have names that differ only in case, such as `alice` and
`Alice`, each is shown with `#` and the first six characters of its fingerprint, `alice#6tvrsb`
and `Alice#lhk6xo`, everywhere the TUI and `vox room read` name them. In the composer,
`@alice#6tvrsb` picks one of them.

Under each name a line says where the two of you stand: `trusted both ways`, `waiting for the
other side` (you trust it, it does not trust you yet), or `not in keyring: trust to read each
other`; `not in keyring · still reads you` for a node you removed that still holds your key from
before. There is no other trust state: no "verified", and no block. Removing a node from your
keyring is how you stop reading it and being read by it. Where the terminal takes only ASCII, the
glyphs are `<>`, `->` and `.`. The words describe local trust and
whether the other member can read your messages in that room. They are not read receipts for
an individual message.

Select a member with the arrow keys while the members pane has the focus, and its card is drawn
under it: the whole fingerprint in groups of four, beside five rows of art drawn from the
fingerprint, as a quick visual check. Compare the groups themselves before you trust a node.

## Trust from the TUI

In the TUI, trust is one action wherever it matters: `t` on a member in the members pane, or
`:trust` and the start of a fingerprint, which the TUI offers beside a node not in your keyring:
on its messages (`(not in keyring · :trust spezmg3w)`), on the line saying it joined, and on a
service it shares. Each opens the same prompt. It shows the node's fingerprint in groups beside
its art, and asks for:

1. their fingerprint, as they gave it to you: paste or type it; spaces, dashes and case do not
   count;
2. your name for them;
3. your identity passphrase, or Enter alone while the keyring is open.

If what you pasted is not this node's fingerprint, nothing is added, and the TUI says so and shows
both: `not trusted: the fingerprint you were given is not this node's — do not trust it; ask them
for theirs again another way. given: … · this node: …`. A wrong identity passphrase adds nothing
either: `the identity passphrase does not match`. When they match, it says `you now trust frank`.

## See your keyring in the TUI

On the room list, `k` opens the keyring view: every node you trust, by your name for it, with its
card. Esc returns to the list.

```text
  alice
    ◥◥◥◥◣◣◣◣◤◤  m4ol surt bsra fsq2 djll
    ◣◣◤◤◥◥◥◥◣◣  wj6f vgoo fiu2 ns76 6n3u
    ◣◣◥◥◣◣◣◣◥◥  ljvt gbvy lkkq
    ◤◤◥◥◤◤◢◢◣◣
    ◥◥◥◥◤◤◥◥◥◥
```

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

Before it acts, Vox says what the node is to lose: `it is to read nothing you write from now on
in "family"; what it already read stays read`, `and to reach none of your services from now on: it
loses ssh in "family"`, and which of its live sessions into your services are to be cut. After,
it reports `your sender key is rotated and everyone still trusted is re-keyed`, the sessions it
cut (`cut: tunnel 1: ann reaching your ssh`, or `cut: none was open`), and that your own sessions
into the other node's services are untouched: those are the other node's keyring's to grant, not
yours. Verify the
fingerprint is absent from `vox trust list`, and inspect any affected service or conversation
from the other side if you need operational confirmation. Do not run this as an experiment on a
family member's or production agent's identity.

For passphrases and paths, see [Commands and local state](reference.md). For a one-way
conversation, see [the trust troubleshooting entry](troubleshooting.md#we-joined-but-cannot-read-each-other).

Source: [trust and node commands](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[the 30-minute keyring window](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-core/src/node/actor.rs),
[how the window is shown](https://github.com/robertelee78/vox/blob/0e27808d2769e34fa678870ecb17ed141caff269/crates/vox-tui/src/ui.rs)
and [TUI state wording](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/ui.rs).
