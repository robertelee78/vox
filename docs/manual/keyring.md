# Identity and keyring

Applies to Vox v0.4.5.

For several computers you own, start with [My computers](#my-computers): enrollment manages
trust between their nodes after approval on both machines. The individual-node steps below are
for another person or a narrower grant. The examples act as `robertgpt`, whose keyring holds
`ann`; commands name their acting node explicitly.

## Your nodes

A node is one identity: its own keys, rooms, keyring and services. Separate personal and agent
nodes make their grants easy to control. A node is not permanently classified as human or agent: a
registered Session stamps its own posts as agent-origin, even if a person also posts through that node.
Use [agent setup](agents.md#set-up-a-machine) to create and wire an agent's node together.

| To | Run |
|---|---|
| Make a node | `vox node create robertgpt` |
| List the nodes on this machine | `vox node list` |
| Unlock a node | `vox node unlock robertgpt` |
| Lock and forget a node | `vox node lock robertgpt` |
| Rename it on this machine | `vox node rename robertgpt robert-laptop` |

`vox node create` asks for the identity passphrase twice, or reads it from `--passphrase-file`.
Leave it empty to make a node with none: Vox then says that the node's key is kept unencrypted, so
anyone who can read its data folder can act as it. There is no command to change a passphrase.

At a terminal, `vox node create` also makes the node Ready. A script creates a protected node
Locked; a node with no passphrase becomes Ready immediately. There
is no backup of a node: its keys never leave the machine. If the machine is lost, make a new node,
and ask everyone who trusted the old one to remove it and trust the new one.

`vox node unlock` makes a node Ready and always remembers it for daemon restarts, updates and
reboots. On a Mac its passphrase is stored in the Keychain, whether typed or supplied through a
file or environment variable. A node with no passphrase needs no secret stored. On a system
without a Keychain, a protected node needs a private persistent passphrase file:
`vox node unlock robertgpt --passphrase-file ~/.vox-robertgpt-passphrase`.
Keep that file in place: the daemon reads it again at each start. Stdin (`-`) and an environment
variable cannot supply a remembered file. There is no option to unlock without remembering.
If remembering fails, unlock returns a failure and describes the resulting state. A previous
remembered entry may remain; if Vox cannot read it, it reports that uncertainty. Correct the
reported problem and retry.

`vox node list` shows each node as **Ready** or **Locked**, with its fingerprint, and
`(remembered)` when Vox has saved how to start it again. A progress mark appears while work is
starting or stopping; an unreadable saved record reports its reason instead of guessing a state.

**Ready** means the node is running and can work. **Locked** means its protected identity needs
unlocking. `vox node lock` closes a protected node's connections, stops its services, wipes its
keys from memory and forgets its remembered passphrase. Its rooms and keyring stay on disk.
An already-open app or terminal connection must not silently start the node again or resume as
a later unlock of the same identity. Unlock and choose the node again to open a fresh connection.
In the Mac app, **Choose Node → Use This Node** opens a fresh connection even when you choose
the same node. It preserves that node's local room and Session drafts and the current reply;
the selected room reopens at General. A failed unlock or credential-store operation shows its
actual result without discarding the draft.
A node made with no passphrase always becomes Ready when Vox runs. Lock or Forget removes any
remembered entry but cannot lock an identity that has no passphrase; Vox says it stays Ready.

`vox node rename` keeps the node's identity, so its fingerprint stays the same. It moves the name
everywhere this machine holds it: the node's directory, its remembered passphrase, the harnesses
wired to it, and the app's choice of node. If a keyring on this machine names the node, the
command prints the `vox trust rename` that updates it.

## When the passphrase is asked for

Vox asks for the identity passphrase in two cases only: when you unlock the node, and when you
change its keyring with `vox trust add`, `remove`, `rename`, `drive` or `read`. Posting, reading,
sharing, and a room's name or retention never ask.

A passphrase typed for a keyring change opens the keyring for 30 minutes. Further changes in that
time do not ask. A passphrase typed to unlock the node does not open it. The separate agent-origin
guard still refuses `vox trust add` and `vox trust drive` from a process carrying a harness's
Session mark, even while the keyring is open. Run those commands in your own terminal outside
the agent session. This guard is not OS security isolation from other programs running as you.
`vox status` shows `keyring asks for the passphrase`, or `keyring open 30m` with the minutes left.

A keyring change takes the passphrase only from a terminal. It never reads a file or
`VOX_IDENTITY_PASSPHRASE`. When a passphrase is needed but there is no terminal, the change is
refused and Vox prints the complete command to run in one. That command carries the actual fingerprint, chosen name and acting node. Copy it
from the refusal only if it describes the change you intend.

## An agent's node

An agent's node follows the same rules. You, the operator, type its passphrase in a terminal
outside the agent's session:

```sh
vox node unlock claude-mac
```

For a trust change on `claude-mac`, use the actual fingerprint compared with its owner, the
chosen local name and `--node claude-mac`. The [offers](#offers-nodes-waiting-for-your-trust) output
provides complete commands for actual offered nodes.

The agent's hook never asks for a passphrase. A passphrase-free node becomes Ready by itself;
for a Locked node the agent gets the command for you:

```text
Vox node claude-mac is Locked; ask the operator to run `vox node unlock claude-mac` in a terminal outside this session.
```

## Compare before trusting

`vox id --node robertgpt` prints your node's whole fingerprint. Get the other person's whole
fingerprint through a way you already trust, such as in person or a call, and compare every character. A short prefix is
not proof. A different key is a different node: if someone replaces their machine, compare the new
fingerprint before you trust it, whatever name it claims.

## Offers: nodes waiting for your trust

When a node joins a room after yours and is not in your keyring, your node offers it to you. So
does a node that trusts you. An offer waits until you accept it, dismiss it, or the node leaves.
Nothing is posted to the room either way. To list offers, run:

```sh
vox trust offers --node robertgpt
```

The offer contains complete accept and dismiss commands for the actual node. Use those from
your terminal output, keeping `--node robertgpt`.

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

After comparing the actual fingerprint, copy its `accept (read)` command from the offers output.
If the node is not offered, construct `vox trust add` with the fingerprint you compared,
`--name ann` and `--node robertgpt`. [Quote each argument](reference.md#commands-you-can-paste).
Then inspect the result:

```sh
vox trust list --node robertgpt
```

The keyring alias is yours alone. Without `--name`, Vox offers the name carried by a copied
identity, or the node's presented name when available. At a terminal, press Enter to accept that
default or type your own alias; if no default is available, you must supply a name. A default is
not proof of identity: compare the fingerprint. Before and after asking for a passphrase when
needed, Vox says what the trust grants:

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

For an initial drive grant, add `--drive` to the actual trust-add command. For an existing
entry, use `vox trust drive` with its full fingerprint from your keyring and `--node robertgpt`.
To withdraw drive, use `vox trust read` with that same fingerprint and acting node.

`vox trust add --drive` grants read + drive from the start. `vox trust drive` adds drive to a node
you trust. `vox trust read` takes drive back: the current private Session view and attention query
are withdrawn. This cannot erase content someone already read or copied; previously visible
text is not evidence of continuing permission.

## Rename a node in your keyring

Use `vox trust rename` with ann's actual fingerprint from `vox trust list --node robertgpt`,
the new name `annie`, and `--node robertgpt`. Quote the actual arguments when constructing it.

Vox prints the new name and the addresses its services now have, such as
`<service>.annie.<room>.vox`. Renaming grants and removes nothing. To change a name, rename. Do
not remove and add again, because removing rotates keys.

## Remove a node from your keyring

Removing a node withdraws its reading and its service access in every room you share. It keeps
what it already read.

Use `vox trust remove` with the intended node's actual fingerprint from your keyring and
`--node robertgpt`. Afterwards, `vox trust list --node robertgpt` shows the remaining grants.

Before it acts, Vox says what the node is to lose and which of its live sessions into your
services it is to cut. Afterwards it reports:

```text
vox: removed f7l2q44g56mzd62nsvck7mofib from your keyring
     your sender key is rotated and everyone still trusted is re-keyed
     cut: none was open
     your sessions into its services are untouched
```

## My computers

A **computer identity** belongs to the daemon and manages its enrolled nodes. It is distinct from
each node's identity and fingerprint. Pair your own computers when you want the managed-node policy
below. To trust someone else, or grant access to only one node, use the individual keyring flow
in this chapter instead. Merely sharing a LAN, OS account name or machine name establishes no trust.

Install Vox on both computers first. Enrollment needs no existing node, node selector or identity
passphrase; the computer commands start the daemon when needed. Run them in your own terminal,
not through an agent. Ready managed nodes apply the policy; Locked nodes need unlocking before
they can apply it.

Computer trust is an operator choice shared by the enrolled daemons. Either computer may create
the invitation: in Vox.app use Add Computer, or run `vox computer invite` on one computer and
`vox computer pair` on the other. If one is already enrolled and the other is individual, the
individual joins that existing group whichever computer issued the invitation. Two individual
computers create a new group. If both already belong to the same group, pairing synchronizes
their existing membership instead of creating another enrollment. Begin on either computer:

```sh
vox computer status
vox computer invite
```

Send the invitation to the other computer through your trusted channel. Paste the complete
terminal command printed by `invite`, or paste the code into Add Computer. Both sides show the
authenticated peer, fixed policy and exact operation, and whether it creates a new group or joins
the identified existing group. Check the entire group identifier when joining an existing group.
Authentication of the code and peer permits this review; it does not grant permission or approve
enrollment. Explicitly approve the same operation on each computer. Each surface names which
computer must act next; approval on one side never substitutes for the other. `--preview`
shows the proposal without approving it. Until computer trust is established, reviewing a code
preserves individual node trust, including choices made after retiring an old group. Pairing grants
no room membership; join the same room and verify a message both ways.

If the daemon restarts after the authenticated invitation is claimed but before the proposal
is recorded, the same computer can authenticate again; another computer cannot take over that
claim. A recorded proposal and its approvals survive restart as the same operation. A changed
operation or group needs a fresh review and both approvals; an approval is not transferred.
Cancel an unused invitation or unapproved proposal on the computer where it is pending. Closing
a window alone leaves it pending. A cancellation cannot withdraw an approval already signed
and retained elsewhere; an incomplete signed attempt may need to expire before it can be closed.
If Vox reports that the other computer's pairing software needs updating, update it and start a
fresh pairing. A connection failure alone does not establish that an update is needed.

If an authenticated computer is already in a different established group, Vox explains the
conflict instead of calling it a bad signature. On the computer to move, review the affected
identities and grants and explicitly choose local replacement. Declining changes no trust.
To keep the existing group, close the review on this computer using the button or the complete
`vox computer cancel` command shown there. That local closure prevents reuse of that proposal
here; it does not cancel or withdraw a signature on the inviting computer.
This preserves identities, local data and signed history; unreachable computers may retain
old access and data. On the inviting computer, close its old proposal and create a fresh
invitation; if it already signed, wait until the incomplete attempt expires before closing.
Closing locally cannot withdraw a signature already retained elsewhere. Both computers must
approve the fresh operation.

In the app's confirmation sheet, review every affected identity in the scrollable list.
**Copy Selected Identity** copies the complete selected name and fingerprint; selecting a row
does not narrow which grants the confirmation affects. Escape or **Cancel** leaves authority
unchanged. Replacement requires the separate explicit destructive action.

If trust changes while a replacement review is open, Vox refuses the stale confirmation.
This includes a later Read/Drive choice for a previously restored, covered node, even when the
group frontier is unchanged. Review again rather than confirming the older affected grants.
The app keeps that refusal below the **My Computers** heading, above the scrollable details;
review the current state before trying again. A refusal is not a completed replacement.

Every managed node can read the other managed nodes. A computer's selected personal node can
drive nonpersonal nodes; personal nodes cannot drive each other. The daemon saves the app's
selection, including when the app is closed. Once `robertgpt` is a Ready local node, a headless
computer can select it too:

```sh
vox computer personal robertgpt
vox computer status
```

To clear that selection instead, run this separate reset command:

```sh
vox computer personal --clear
```

The roster follows node creation, rename and removal. Fingerprints establish identity; names
only label it. Local aliases survive presented-name changes. Status shows configured direct
group Read and personal-to-nonpersonal Drive separately from application receipts and observed
connectivity. Receipts do not prove that a computer is currently online, nor do they establish
room membership, consent or Session access. Use `vox computer status --details` for complete
identities, revisions, counters and optional node-management actions.

If a computer-policy update meets room history that is still being saved, the daemon retains
the accepted update until that exact publication settles instead of discarding it as a temporary
busy error. Trust-dependent actions can report that computer policy is refreshing in the meantime.
The same update then continues without another approval or manual node grants; already saved
history remains available. Storage failures and changed authority remain errors, not successful
policy application.

To remove a computer, review its full fingerprint and nodes in `vox computer status --details`,
then use the exact displayed frontier:

Construct `vox computer remove` with the intended computer's full fingerprint from that
status, and its current frontier in `--confirm`. Both values come from the actual status;
neither is a reusable example.

This withdraws all trust in that computer's nodes, including individual grants made before
pairing. Remaining computers apply the removal when they receive it; pending does not mean
confirmed. This cannot erase messages or files the removed computer already received. Restart
or an old roster cannot restore it. Bringing it back requires a fresh two-sided enrollment.
After removal you can instead make a deliberate new individual grant with `vox trust add`.

While a received removal is being applied, a room read can say `computer policy is refreshing;
retry`. Check `vox computer status` for the pending application; do not repeat the removal,
regrant trust or restart the daemon to make that application finish. Read-only governance
preparation resumes the existing application without replaying committed withdrawals.
Brief room reads do not fail that application: its existing preparation waits for the room,
without requiring another approval or a daemon restart.

Copying a node folder does not transfer management. For an intentional move, the existing
manager releases the exact node to one enrolled destination, then the destination approves:

On the existing manager, use `vox computer binding release` with the actual node fingerprint,
the destination computer's fingerprint in `--destination` and the reviewed current frontier in
`--confirm`. On the destination, read its updated `vox computer status`, then use
`vox computer binding transfer` with the same node fingerprint and that destination's current
frontier in `--confirm`.

The node's protected vault must be available and unlocked on the destination to sign its new
binding. No command guesses ownership from a name or copied fingerprint. If the previous
manager is lost, remove it first, then explicitly approve recovery on the destination with
`vox computer binding recover` with the actual node fingerprint and the current destination
frontier in `--confirm`. Recovery retains the old binding and removal evidence. If a node key was compromised, use a new node identity instead.

If this computer has been removed and the old group cannot be continued, use
`vox computer retire`. Review the computers and covered authority and confirm explicitly;
Vox checks that the reviewed state has not changed before retiring it locally. This preserves
identities, data and signed history and removes covered grants before a fresh pairing. It does
not erase data or claim revocation on unreachable computers.

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
