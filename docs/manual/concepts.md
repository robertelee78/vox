# How Vox fits together

Applies to: the shared product model. Commands and lifecycle details differ by release; the
task chapters describe v0.3.0.

## A node is an identity

A node has cryptographic keys and a fingerprint. It is not a username at a provider and not
a synonym for a physical device. Your person's identity and an agent's identity are different
nodes. Losing identity data is not solved by asking a central operator to reset an account.

In v0.3.0 one daemon per data root hosts every node on the machine, and each node runs in full
while it is attached. A command names the node it acts as with `--node`; with only one node
attached, it acts as that one. v0.2.10's `--profile` is gone; see
[Coming from v0.2.10](development.md).

## A room is a shared space

A room's messages are kept and replicated by its members' nodes; no server holds a copy. A
room link (`vox://…`) finds the room; the room passphrase is sent separately, by another way.
A room is usually made for one purpose: members come and go, leaving deletes it from that
node, and its creator or an admin can end it, which deletes it on every member's node. A two-person conversation is a room too.
There is no username directory to search for a stranger or central inbox guaranteeing that
messages arrive while every member is offline.

Joining a room and trusting its members are separate acts. Room membership alone is not
permission to read everyone's messages or reach their services.

## Trust has a direction

When you trust Ann's node, you make a decision about that fingerprint. It covers every room
you share with it, now and later, and services you offer in those rooms. Ann's decision to
trust you is separate; do both for ordinary two-way conversation.

Trust is not a vote. Another member's endorsement does not add a key to your keyring. Removing
trust stops future access governed by your decision; it cannot take back messages or files
someone already obtained.

## Names belong to the viewer

`ann`, `robertGPT`, and an agent alias are your local names for fingerprints. Another person
can call the same node something else. Someone writing “I am Ann” in a message does not make
that their authenticated display name. Compare the fingerprint before assigning the name.

The same idea applies to room names. A room ID identifies the room; `family` is a convenient
local label. Use the selector your version's command help accepts.

## A service is an offer, not a public tunnel

A node can share a named local service with a room. Reach depends on shared room membership
and the host's trust decision. Each member reaches it as `service.node.room.vox`, where the node
and room parts are that member's own names for them, so two members may see different
addresses for the same service. It is not a public web link and does not install global DNS.
The local proxy (`vox up`) or a forward (`vox forward`) bridges your ordinary tool into Vox.

A file announcement is a message; its bytes are fetched from a live offer. Seeing the
announcement does not prove that the sender is still serving the bytes.

## An anchor is a bridge

Directly reachable peers need no anchor. When two hosts cannot otherwise find or reach each
other, a user-run anchor provides rendezvous and may relay encrypted packets. It is not a
room administrator, cloud backup, or place that can decrypt your conversation.

## What encryption does not promise

Vox protects content in transit between participating nodes. It does not make a compromised
endpoint safe, prevent a recipient retaining a copy, or hide every communication pattern.
If an agent receives a room message as context, that context can enter the agent's configured
model provider; Vox is not a local-model policy or provider-isolation boundary.

Cryptographic identity tells you which key signed something. Comparing that fingerprint
with the intended person or agent is still a human trust decision.

Continue with [Your first shared room](first-room.md) or [Get help safely](getting-help.md).

Sources: [foundation and limits](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-001-vox-foundation-vision-threat-model-and-principles.md),
[v0.3.0 command definitions](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/cli.rs),
[the daemon and node model](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-026-daemon-and-nodes.md)
and [service addresses](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-017-room-bound-services.md).
