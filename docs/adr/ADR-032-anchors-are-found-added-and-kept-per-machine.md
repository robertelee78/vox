# ADR-032: Anchors Are Found, Added and Kept per Machine

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.4 (the decider's Q&A, 2026-10-10, and his answers to this ADR's
open questions, the same evening). Nothing in this ADR is built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: anchors, nat, discovery, settings, links, rooms, macos
**Related**: ADR-007, ADR-012, ADR-014, ADR-016, ADR-017, ADR-023, ADR-026, ADR-028
**Inputs**: the decider's product Q&A of 2026-10-10 (Q5) and his answers to the open questions
(searching for an anchor at room creation instead of any home-network concept; who sets a room's
anchors); the onboarding evaluation of 2026-10-10, its anchor measurements (§5).

## Context

An anchor bridges hosts that cannot otherwise find each other, and nothing else needs one
(ADR-012 N-1–N-8). On 2026-10-10 the decider found that the New Room sheet says nothing about
anchors and that Vox does not find the anchor on his own network: "I think anchor is needed for this
room to be joinable by some nodes on different networks"; "it's not clear to me how we can
automatically use an anchor if it exists."

Today an anchor reaches a node in three ways, none of them visible: a hand-edited `anchors` file,
per node since ADR-026 F-1 and read from the account's file when the node has none (ADR-017 7.1);
`--anchor`, forgotten at the next attach; and a link, whose anchors are kept for that room only.
Nothing finds an anchor on the local network: nearby discovery (`node::nearby`) finds room members
only. The app shows no anchor, and `vox status` names none.

The decider's answer (Q5) was that anchors are addable by hand in Settings, that a room can carry
its own, and that Settings lists each with its source and reachability; they stay a bridge only.
His first answer also had anchors discovered on the local network and used everywhere. His answer
to the open question replaced that: there is no home-network concept and no automatic use of an
anchor found on the network. Instead, searching the network for an anchor is a choice the person
makes when creating a room, next to the room's optional anchor field, and an anchor found that way
is that room's. Of who sets a room's anchors: "Seemingly only the room creator or room admin should
do that."

## Requirements

### 1. Bridge only

- **AN-1.** ADR-012 N-1–N-8 MUST hold unchanged: nothing MAY wait on, fail on or blame an anchor
  when the peer is directly reachable, and when one is missing or down Vox MUST say truthfully what
  that costs. A room with no anchor MUST be created, joined and used as today.

### 2. One list per machine

- **AN-2.** Each daemon MUST keep one anchor list for its data root. It MUST hold the anchors added
  by hand on this machine (§4), which every node of that daemon MUST dial for its own reach, and
  MUST show beside them every room's own anchors (§3), each used for its room only.
- **AN-3.** Each entry MUST record its sources, one or more of: **added by hand** and **from room
  <name>**. There MUST be no source "found on this network": an anchor found by a search (AN-6) is
  the room's.
- **AN-4.** A node's own `anchors` file and the account's `anchors` file, written by v0.4.0 or later,
  MUST be merged into the list at the first start of a release with this ADR, each line with source
  added by hand, and then removed (ADR-026 F-3). The anchors a node kept from a link for one room
  MUST become that room's anchors on that node, with source from room <name>.

### 3. A room's anchors

- **AN-5.** A room MUST carry its own anchors (ADR-012 N-34), stated on the room's log as a signed
  governance entry, as the room's shared name is (ADR-028 R-1): the causally last statement by the
  creator or an admin MUST win. Every member's node MUST dial the room's anchors for that room.
- **AN-6. Set at creation.** The New Room sheet and `vox room create` MUST offer an optional anchor
  field (`<fingerprint>@<address>`, or a host name and port) and, next to it, the choice **Search the
  network for an anchor** (`--find-anchor` at a terminal). The search MUST run only when the person
  chooses it. It MUST ask on the local network, on nearby's group with its TTL of 1, and MUST name
  no room; a daemon with an anchor attached (ADR-026 N-5) MUST answer with the anchor's fingerprint
  and the addresses it serves on, and MUST NOT announce itself unasked. The sheet MUST show each
  anchor found, with its short fingerprint and address, and the ones the person keeps (every one
  found, unless the person removes it) MUST become the room's anchors. Finding none MUST say so in
  one sentence and MUST NOT hold up the create.
- **AN-7. Authenticated.** A dial to an anchor found by a search MUST be authenticated as the
  fingerprint it answered with, so a forged answer costs a failed dial and nothing more.
- **AN-8. Only the creator or an admin.** Only the room's creator, or an admin it delegated
  (ADR-007 G-5; ADR-023 RL-2.1), MAY set or change the room's anchors: at creation, and later from
  the room's menu in the app and `vox room anchors <room> add|remove` at a terminal, both of which
  MUST offer the same field and search. A change by anyone else MUST be refused, saying that the
  change is the admin's (`Fault::NotAdmin`), and every member MUST ignore a statement not signed by
  the creator or an admin.

### 4. Added by hand

- **AN-9.** Settings › Network in the app, and `vox anchor add`, `vox anchor list` and
  `vox anchor remove` at a terminal, MUST add an anchor to this machine's list from
  `<fingerprint>@<address>` or a host name and port, and remove one. An anchor added by hand MUST
  NOT become any room's anchor by itself.

### 5. In a link

- **AN-10.** The New Room sheet and `vox room create` MUST show the anchors the room's link will
  carry.
- **AN-11.** A link MUST carry, after the inviting host (ADR-012 N-3), the room's own anchors, then
  the inviting machine's anchors added by hand, up to `MAX_LINK_ANCHORS`. The joiner MUST keep the
  room's own anchors as that room's, and MUST use the inviter's hand-added ones only to reach the
  inviter for that join, never as the room's.

### 6. Shown truthfully

- **AN-12.** Settings › Network, `vox anchor list` and `vox status` MUST list each anchor with its
  short fingerprint, its address, its sources, and whether this daemon reached it: "reached 2 min
  ago" or "not reached since 14:02", from the daemon's own dials, never a guess. The room's
  members panel or menu MUST show the room's own anchors the same way.
- **AN-13.** `vox status --json` MUST give each anchor's fingerprint, addresses, sources and reach.

### 7. Upgrade

- **AN-14.** The room's anchors entry (AN-5) and the machine's list (AN-2) are format changes
  (ADR-026 F-3): v0.4.4 MUST raise the data root's format and MUST upgrade, automatically and
  before anything else is written, every data root a release since v0.4.0 wrote (AN-4), and MUST
  prove it on a data root the shipped v0.4.3 binary wrote, with nothing lost.

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-017 7.1–7.2; ADR-026 F-1, F-2 | Anchors are a per-node setting, read from the account's file when the node has none; `--anchor` merges for one command | One list per data root of anchors added by hand, dialled by every node (AN-2), with sources (AN-3); `vox anchor add` keeps one (AN-9) |
| ADR-012 N-34 | The configured anchors are dialled and named in links, and persisted per room | A room's anchors are a governance entry set by its creator or an admin (AN-5, AN-8); links carry them, then the inviter's hand-added ones (AN-11) |
| ADR-028 R-1 | The room's shared name is a governance entry | So are its anchors (AN-5) |

## Consequences

- Nothing is found or used automatically: an anchor on the local network serves a room only when
  that room's creator or an admin chose it, by search or by hand.
- A search tells the local network that this machine is looking for an anchor, and an anchor's
  answer tells it that an anchor runs there, and its fingerprint. Any device on the network can
  answer. A hostile anchor kept by the person can degrade availability only, never
  confidentiality or authenticity (ADR-012 N-34), but it learns the rendezvous records it holds
  for that room (ADR-023 RL-6.1) and their addresses.
- Every member of a room dials the anchors its creator or admins set, and no other member can add
  one to the room.

## Related ADRs

Depends on ADR-012, ADR-026. Amends ADR-012 (N-34), ADR-017 (7.1, 7.2), ADR-026 (F-1, F-2) and
ADR-028 (R-1). Cited: ADR-007, ADR-014, ADR-016, ADR-023.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
