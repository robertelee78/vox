# How Vox fits together

This page explains the ideas behind Vox: what a node, a room and trust are, how services and
anchors fit in, and what encryption does and does not cover.

## A node is an identity

A node has its own keys, and a fingerprint that names them. It is not an account at a provider,
and not a device: your identity and each agent's identity are separate nodes, and one machine can
hold several. No central operator can reset a node. If its keys are lost, it is gone, and you
make a new one.

One daemon on the machine runs every node that is attached. A command names the node it acts as
with `--node`, and with only one node attached it acts as that one.

## A room is a shared space

A room's messages live on its members' nodes. No server holds a copy, so there is no directory
of users to search and no inbox that keeps messages while every member is offline. A room link
(`vox://…`) tells a newcomer where to find the room. The room passphrase, sent another way, lets
them in.

A room is usually made for one purpose. Members join and leave, and its creator, or an admin the
creator names, can end it, which deletes it on every member's node. A conversation between two people is a room too.
A room has one name, the same for every member. Its ID identifies it whatever the name is, and
commands take either.

## Trust has a direction

Joining a room makes you a member. It does not let you read anyone. Reading takes trust from both
sides: Ann reads what you write once you add her node to your keyring, which sends her your key,
and her node trusts yours, which lets it take the key. Each of you decides separately. Your trust
covers every room you share with Ann, now and later, and the services you share there.

Trust is not a vote. Another member's trust in a node adds nothing to your keyring. Removing a
node from your keyring stops what it reads from then on. It cannot take back what it already
read.

## Names belong to you

`ann` and `robertGPT` are local names for fingerprints. Someone else can call the same node
something else, and a message saying "I am Ann" proves nothing. Compare the fingerprint, then
choose the name.

## A service is an offer to the people you trust

A node can share a local service, such as SSH, in a room. Each member reaches it at an address
such as `ssh.robertgpt.family.vox`, built from that member's own names for the node and the room.
Its canonical address, made of fingerprints and IDs, is the same for every member and is the one
to send. Only members the sharing node trusts reach it. It is not a public web address. The
daemon's local proxy, or `vox forward`, connects your ordinary tools to it.

A shared file is a message. Its bytes come from the sharer's machine, which serves them until the
message expires or the sharer stops. A message about a file does not prove the file is still
served.

## An anchor is a bridge

Nodes that can reach each other directly need no anchor. When two hosts cannot find or reach each
other, for example when both are behind NAT, an anchor that both can reach introduces them and
may relay their encrypted packets. You run it yourself. It holds no room key and cannot read
anything. A node learns its anchors from its anchors file, from `--anchor`, and from the room
links it joins with ([when an anchor is needed](services.md#when-an-anchor-is-needed)).

## What encryption covers

Vox encrypts what travels between nodes. It does not make a compromised machine safe, stop a
recipient from keeping a copy, or hide every pattern of who talks to whom. When an agent reads a
room message, the message can reach the agent's model provider.

If a node's memory or disk is stolen, Vox recovers by itself, against a future quantum computer
too, as long as the thief only listens. Every key a node hands to another member travels in a
fresh handshake made for that key alone. The next key the robbed node hands out is safe again,
and keys sent to it are safe again within seven days. A room recovers at its next key rotation.
None of this helps against a thief who uses the stolen identity to act as the node.

Some limits apply:

- A member that offers no fresh one-time key within 30 seconds gets a key that recovers only
  within seven days.
- If you copy a node's data and later put the copy back, the copy brings back its old one-time
  keys for up to seven days.
- A wrong clock adds at most ten minutes to the seven days.

When one node connects to another, the answering node proves it holds the expected key on that
same connection, before the caller says who it is. A stranger at the address learns nothing about
the caller, and a proof copied from one connection fails on another. Every refusal looks the same
and takes the same time, so probing an address reveals nothing. Each address may ask only so
often, and half-open connections are capped. Anyone who knows a node's fingerprint can still test
whether that node answers at an address: the fingerprint is not a secret.

A fingerprint tells you which key signed something. Whether that key is the person you mean is
your decision, made by comparing it.
