# Your first shared room

Applies to: v0.2.10. Allow a few minutes and keep both machines online. You need another person
whose identity you can compare through an existing trusted channel.

This walkthrough uses the released, profile-based CLI. It does not use development commands
such as `vox node create` or `--node`. You will create a room, exchange trust, then confirm
that a message arrives **in each direction**.

## 1. Each person creates an identity

On each person's machine, before starting a daemon:

```sh
vox --version
vox id --profile family
```

On first use Vox creates this profile's identity and asks for its identity passphrase. Choose
one you can retain; this is not the room passphrase. Later uses unlock the same identity rather
than register an account. Record the full 52-character fingerprint printed by `vox id`.

Exchange those fingerprints and compare them through a channel you already trust, such as an
in-person conversation or a known person's call. Do not accept a replacement fingerprint
solely because an unknown sender says “it's me”. A fingerprint is public, but verifying whose
fingerprint it is is your decision.

## 2. Each person keeps a daemon running

In one terminal on each machine:

```sh
vox daemon --profile family
```

Enter that machine's identity passphrase when asked. Leave this process running; subsequent
commands in this walkthrough go in a **second terminal**. The daemon holds the identity and
rooms while clients ask it to act. Closing it interrupts this profile's networking.

Confirm in the second terminal:

```sh
vox room list --profile family
```

A new profile has no rooms. “No node is running” is not an empty room list: check that both
terminals selected the same profile, data root and config root. `vox node` is an anchor in
this release, not a substitute for `vox daemon`.

## 3. One person creates and invites

The person creating the room runs:

```sh
vox room create --profile family --name family
vox room list --profile family
```

Vox asks for the new room's passphrase and confirmation. This is a separate secret from either
person's identity passphrase. Copy the room ID from the output/list. In examples below,
replace `ROOM_ID` with it:

```sh
vox room invite --profile family ROOM_ID
```

Send the complete `vox://…` address to the other person. Send or say the room passphrase by a
different channel. Keep a room member online for the join. If both hosts cannot reach each
other directly, read [when an anchor is needed](services.md#when-an-anchor-is-needed).

## 4. The other person joins

The invited person runs this in the second terminal, replacing the example URL with the
complete address received:

```sh
vox room join --profile family 'vox://…' --name family
vox room list --profile family
```

Enter the **room** passphrase at its prompt. Joining persists the room locally. It does not
give either person permission to read the other's messages. The name `family` is local;
the two people may choose different names for the same room.

Both people can inspect membership:

```sh
vox room roster --profile family ROOM_ID
```

The two expected fingerprints should be present. A refused join and a timeout mean different
things; use the [join troubleshooting entries](troubleshooting.md#i-cannot-join-a-room)
instead of repeatedly changing the passphrase.

## 5. Each person trusts the other

The first person substitutes the other person's previously compared full fingerprint:

```sh
vox trust add --profile family FULL_FINGERPRINT --name ann
vox trust list --profile family
```

The other person substitutes the first person's fingerprint and chooses their local alias:

```sh
vox trust add --profile family FULL_FINGERPRINT --name robertGPT
vox trust list --profile family
```

These are two independent decisions. Trust allows the named node to read what you share and
reach your shared services in **every room you share**, including future rooms. It is not
restricted to this tutorial room. A keyring change may ask for your identity passphrase.

## 6. Prove receipt both ways

The first person posts:

```sh
vox room post --profile family ROOM_ID "hello from robertGPT"
```

The second person reads, confirms that exact message appeared, and replies:

```sh
vox room read --profile family ROOM_ID
vox room post --profile family ROOM_ID "hello back from ann"
```

The first person then runs:

```sh
vox room read --profile family ROOM_ID
```

You are done when each person sees the other's text. Local post success means the local node
accepted a post, not that someone else read it. If one side cannot read, check both keyrings,
membership and connectivity using [Troubleshooting](troubleshooting.md#we-joined-but-cannot-read-each-other).

## Use the terminal interface instead

For an interactive room list, stop this profile's daemon deliberately with Ctrl-C, then run
`vox tui --profile family`. This release allows only one process to hold a profile. Do not
run the TUI and daemon over the same profile at once.

The TUI offers `:new`, `:invite`, `:join`, `:open`, `:close`, `:lock` and `:unlock`. The members
pane states trust in words. The CLI walkthrough above makes each step explicit; use the same
fingerprints and room IDs whichever client you choose.

Next: [Rooms and messages](rooms.md), or [Identity and keyring](keyring.md).

Source: [released command definitions](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs)
and [room operations](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/room_cli.rs).
