# ADR-032: Anchors Are Found, Added and Kept per Machine

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Proposed (the decider's Q&A, 2026-10-10). Nothing in this ADR is built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: anchors, nat, discovery, settings, links, macos
**Related**: ADR-012, ADR-014, ADR-016, ADR-017, ADR-023, ADR-026, ADR-028
**Inputs**: the decider's product Q&A of 2026-10-10 (Q5); the onboarding evaluation of 2026-10-10,
its anchor measurements (§5).

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

The decider's answer: anchors are discovered on the local network automatically, addable by hand
in Settings, and a room can carry its own; all of a machine's anchors are used by every room and
node on it, so links carry them; Settings lists each with its source and reachability. They stay a
bridge only.

## Requirements

### 1. Bridge only

- **AN-1.** ADR-012 N-1–N-8 MUST hold unchanged: nothing MAY wait on, fail on or blame an anchor
  when the peer is directly reachable, and when one is missing or down Vox MUST say truthfully what
  that costs.

### 2. One list per machine

- **AN-2.** Each daemon MUST keep one anchor list for its data root, and every node and every room
  of that daemon MUST use every anchor on it.
- **AN-3.** Each entry MUST record its sources, one or more of: **found on this network**, **added
  by hand**, and **from room <name>**.
- **AN-4.** A node's own `anchors` file and the account's `anchors` file, written by v0.4.0 or later,
  MUST be merged into the list at the first start of a release with this ADR, each line with source
  added by hand, and then removed (ADR-026 F-3).

### 3. Found on the network

- **AN-5.** A daemon with an anchor attached (ADR-026 N-5) MUST announce it on the local network, on
  nearby's group and with its TTL of 1, with the anchor's fingerprint and the addresses it serves on.
  The announcement MUST name no room.
- **AN-6.** A daemon that hears an announcement MUST add that anchor to its list with source found on
  this network, and use it. A dial to it MUST be authenticated as the announced fingerprint, so a
  forged announcement costs a failed dial and nothing more.

### 4. Added by hand

- **AN-7.** Settings › Network in the app, and `vox anchor add`, `vox anchor list` and
  `vox anchor remove` at a terminal, MUST add an anchor from `<fingerprint>@<address>` or a host
  name and port, and remove one.
- **AN-8.** Removing a found anchor MUST put it on the machine's blacklist: discovery MUST NOT add it
  again until the person adds it by hand.

### 5. Carried by a room

- **AN-9.** A room MUST carry its own anchors in its record (ADR-012 N-34), and each of them MUST
  also be on the machine's list with source from that room.
- **AN-10.** The New Room sheet and `vox room create` MUST show the anchors the room's link will
  carry, and MUST let the person add one for this room.
- **AN-11.** A link MUST carry, after the inviting host (ADR-012 N-3), the room's own anchors, then
  those added by hand, then those found on this network, up to `MAX_LINK_ANCHORS`.

### 6. Shown truthfully

- **AN-12.** Settings › Network, `vox anchor list` and `vox status` MUST list each anchor with its
  short fingerprint, its address, its sources, and whether this daemon reached it: "reached 2 min
  ago" or "not reached since 14:02", from the daemon's own dials, never a guess.
- **AN-13.** `vox status --json` MUST give each anchor's fingerprint, addresses, sources and reach.

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-017 7.1–7.2; ADR-026 F-1, F-2 | Anchors are a per-node setting, read from the account's file when the node has none; `--anchor` merges for one command | One list per data root, used by every node and room (AN-2), with sources (AN-3); `vox anchor add` keeps one (AN-7) |
| ADR-012 N-34 | The configured anchors are dialled and named in links, and persisted per room | The machine's list, found, by hand and from rooms, is dialled and carried (AN-2, AN-11) |
| ADR-026 D-3 | The daemon owns LAN discovery of members | Also announcing and hearing anchors (AN-5, AN-6) |

## Consequences

- An anchor started on the local network serves every room on every Mac that hears it, with no
  step for anyone.
- Any device on a local network the Mac joins can announce itself as an anchor. A hostile anchor
  can degrade availability only, never confidentiality or authenticity (ADR-012 N-34), but it learns
  the rendezvous records it holds for this machine's rooms (ADR-023 RL-6.1) and their addresses.
- An anchor's announcement tells the local network that an anchor runs there, and its fingerprint.

## Related ADRs

Depends on ADR-012, ADR-026. Amends ADR-012 (N-34), ADR-017 (7.1, 7.2) and ADR-026 (D-3, F-1, F-2).
Cited: ADR-014, ADR-016, ADR-023, ADR-028.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
