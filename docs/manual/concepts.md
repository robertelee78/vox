# How Vox fits together

Applies to: the shared product model. Commands and lifecycle details differ by release; use
the task chapter matching your installed version.

## A node is an identity

A node has cryptographic keys and a fingerprint. It is not a username at a provider and not
a synonym for a physical device. Your person's identity and an agent's identity are different
nodes. Losing identity data is not solved by asking a central operator to reset an account.

Released v0.2.10 selects local identity state with `--profile`. The development architecture
can attach several nodes to one daemon and selects actions with `--node`. Do not substitute
one flag for the other without checking your version.

## A room is a shared space

A room's messages are kept and replicated by its members' nodes. An invitation identifies
the room; the room passphrase is sent separately. A two-person conversation is a room too.
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

A node can offer a local service to a room. Reach depends on shared room membership and the
host's trust decision. A Vox service address is not a public web link and does not install
global DNS. The local proxy or forward bridges your ordinary tool into Vox.

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

Sources: [foundation and limits](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/docs/adr/ADR-001-vox-foundation-vision-threat-model-and-principles.md),
[released trust commands](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs),
and [development daemon and node model](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/docs/adr/ADR-026-daemon-and-nodes.md).
