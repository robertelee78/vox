# Identity and keyring

Applies to: v0.2.10. Examples use the `family` profile. Keep that selection consistent with
the daemon or TUI already running on your machine.

## Compare before trusting

Your fingerprint identifies your node's key material. `vox id --profile family` prints it;
on first use it also creates an identity, so this is not a read-only probe for an arbitrary
nonexistent profile. Obtain it before the first-room daemon step as shown in
[Your first shared room](first-room.md).

Ask the other person for their **whole fingerprint** through an established channel and
compare it with the intended node. Do not trust a short prefix as proof that two full
fingerprints match. The CLI can resolve some unambiguous known prefixes, but that is a
selection convenience, not an identity-verification method.

A different key is a different node. If someone replaces their machine or agent identity,
compare the new fingerprint and decide whether to remove the old one; do not automatically
trust a replacement because it claims the old name.

## Add a node to your keyring

Prerequisite: the fingerprint has been compared, and this is the identity you intend to act as.

```sh
vox trust add --profile family FULL_FINGERPRINT --name robertGPT
vox trust list --profile family
```

Choose a name meaningful to you. It is local and never registers a username. In a terminal,
Vox asks for a name if `--name` is omitted. In automation, give one explicitly.

This grants the node access governed by your trust decision across **all shared rooms**,
including ones you join later. It is not just permission for the currently open room or one
file. The other node makes its own independent decision to trust you. For a conversation,
confirm a message can be read in each direction.

The running node can handle trust changes through its control socket. A keyring change asks
for the identity passphrase when its authorization window has expired; do not put that
passphrase in `--identity-passphrase`, which is intentionally refused.

## Understand the member pane

The released TUI pairs state with words, including `trusted · reads you` and
`trusted · cannot read you yet`. These describe local trust and whether the other member
can read your messages in that room. They are not read receipts for an individual message.

If the state and your expectation differ, check each person's selected profile and keyring,
then connectivity. Do not add an unfamiliar fingerprint simply to silence a warning.

## Remove trust

Before removing a node, understand the scope: its access to your future messages and shared
services is withdrawn across the rooms you share. Sender keys change; live service sessions
may be cut. The node retains anything it already read or copied. The room membership and
your local naming choices are not a guarantee that earlier data disappears remotely.

```sh
vox trust remove --profile family FULL_FINGERPRINT
vox trust list --profile family
```

Verify the fingerprint no longer appears in your keyring, and inspect any affected service
or conversation from the other side if you need operational confirmation. Do not run this
as an experiment on a family member's or production agent's identity.

## Names and versions

This release has `trust add`, `trust list` and `trust remove`. Do not follow a development
`vox trust rename` example against v0.2.10. Do not remove and re-add a trusted node merely
to simulate a cosmetic rename: removal has real access and key-rotation consequences.

For passphrases and paths, see [Commands and local state](reference.md). For a one-way
conversation, see [the trust troubleshooting entry](troubleshooting.md#we-joined-but-cannot-read-each-other).

Source: [released trust command definitions](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs)
and [released TUI state wording](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/ui.rs).
