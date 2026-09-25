# PRD-001: Legitimate transport modes

**Status**: draft for the decider's review — 2026-09-24. Nothing in this document is built unless it
says so; every requirement is written as what the product **must** do.

**Source**: a product-management interview with the decider on 2026-09-24, and a read-only research
pass over `origin/main` 96c47ed (v0.2.7) the same day (ruflo `research-synthesis`,
`vox-research/transport-legitimacy-2026-09-24`). Defects in §4 were read in code; none has yet been
driven against the shipped binary.

## 1. Who this is for

Vox is built for the decider and his family, and for the agents they run. It is **not** built for mass
consumption. When usability and a simple, enforceable security model conflict, the security model wins;
friction for this audience can be fixed later.

## 2. Principles

1. **One identity per node.** A laptop, a phone and a NAS are three nodes, each admitted by the normal
   join and consent flow. There are no linked devices, no identity-versus-device key layer, and no owner
   relationship between nodes. Losing a device means untrusting that one node.
2. **No typed humans or agents.** Every participant is a node. Nothing in the product may branch on
   whether a node is "a person" or "an agent".
3. **Names are local.** Wire formats carry fingerprints. What a person sees is the name they gave a node
   in their keyring when they approved it, and the nickname they gave a room when they joined it.
   Nothing is published or global.
4. **Anchors are dumb pipes.** An anchor does rendezvous and relay. For rooms it is not a member of, it
   stores nothing.
5. **Say honestly what a feature guarantees.** Disappearing messages are look and feel, not a security
   property: nothing proves a client pruned.
6. **Proof is the shipped binary.** Every requirement below is accepted only by a gate that drives the
   `vox` binary as a person would, with a mutation check (ADR-018).

## 3. Requirements

### 3.1 Rooms and scale

- **R1.** A room **must** have no lifetime limit on the number of messages. Reopening a room, restarting a
  node and a cold catch-up sync **must** work at any history size.
- **R2.** A room **must** work with about 500 member nodes.
- **R3.** The per-author rate quota **must** be removed. Invitees are trusted and agents must not be
  throttled. Agent loop control is also out of scope for now; it can be added back later.
- **R4.** Sync **must** stay bounded against a malformed or oversized request (this is correctness, not a
  quota): a request for entries the node does not hold, or an absurd range, must not wedge a room.
- **R5.** A node **must** serve a room's log only to members of *that* room.

### 3.2 Retention and disappearing messages

- **R6.** History is kept **forever by default**.
- **R7.** A room's admin **must** be able to set disappearing messages for the room — 1 hour, 1 week,
  1 month or a custom duration — and change it later.
- **R8.** Shortening retention **must** apply retroactively: older messages are removed on every node as
  the change syncs.
- **R9.** A node **must** be able to set its own retention. Where the room's and the node's differ, the
  **shortest wins**.
- **R10.** An expired message **must** leave nothing visible. The signed skeleton is kept internally so
  sync and fork detection keep working.

### 3.3 Keys, history and ordering

- **R11.** A member **must** be able to read another member's messages even if the two are never online at
  the same time, **provided some always-on member node** (e.g. the NAS) is in the room. Sealed key
  packages travel through member nodes, not through the anchor.
- **R12.** When approving a newcomer, the approver **must** be able to choose "from approval onward" or
  "full history" for their own messages. The default is **from approval onward**.
- **R13.** Messages **must** appear in the **same order on every node**.
- **R14.** Sender keys no longer needed **must** be deleted (forward secrecy), consistent with R12.

### 3.4 Agent comms

- **R15.** Addressing (`to`) **must** use fingerprints on the wire and display keyring names.
- **R16.** An urgent message **must** wake an idle agent on another node **within seconds**, without
  anyone typing. `vox room tail` and the TUI **must** show messages that arrived by sync.
- **R17.** Claims: whoever files a work item **must** be able to mark it as needing a hard lock.
  - Unmarked items may race.
  - Only the holder releases a claim.
  - If the holder goes silent, another member may ask to take it over, and the claim transfers when no
    answer comes within a window.
- **R18.** Files use a **pull** model. `vox share` **must** serve a file or folder over a room-bound HTTP
  service and announce its name, size and SHA-256. The receiver pulls with any tool (curl, rsync) or with
  Vox.
  - Downloads land in `~/Downloads` by default; the location is configurable.
  - The sender's file name is sanitised and never overwrites an existing file.
  - The file is verified against its hash before it appears.
- **R19.** Text injected into an agent's context **must** keep each message attributed to its true
  author. One author must not be able to forge another's lines.

### 3.5 Tunnels and naming

- **R20.** `ssh nas.family.vox` **must** work, where `nas` is my keyring name for the node and `family` is
  my local nickname for the room. The same node reached through two rooms has two names.
- **R21.** `.vox` lookups leaking to system DNS is **accepted**.
- **R22.** Untrusting a node **and** removing a service **must** both cut live sessions immediately.
- **R23.** A refused connection through `vox up` or `vox forward` **must** fail immediately for the app. The
  local terminal or log **must** state the reason whenever this node knows it. The remote side learns
  nothing new.
- **R24.** A forward **must** survive the host restarting or the path changing.

### 3.6 UDP and virtual LAN

- **R25.** Vox **must** carry any UDP traffic between members: DNS, mosh, calls, games, media and
  WireGuard.
- **R26.** Packets larger than one datagram **must** be fragmented and reassembled inside Vox.
- **R27.** Relayed UDP **must** behave like UDP: late packets are dropped, never stall later ones. This
  changes how relays carry traffic.
- **R28.** Eventually, a "family LAN" mode **must** provide a virtual network interface so that apps
  relying on discovery (Plex/Jellyfin, Chromecast, games) work. This comes after UDP forwarding.

### 3.7 App API and the chat/calls app

- **R29.** A separate program **must** be able to open a live stream or datagram flow to a member node
  through Vox. This is the foundation for the decider's next project: a chat app with voice and video
  calls and agent rooms.
- **R30.** Desktop apps talk to the local `vox` node. Mobile apps embed the node as a library.
- **R31.** Platforms first: **macOS, Linux, iOS**.
- **R32.** Calls: **1:1 first**, then small-group mesh.

### 3.8 Anchors

- **R33.** Any always-on node can act as an anchor.
- **R34.** For rooms it is not a member of, an anchor **must** store nothing: it does rendezvous and relay
  only. This reverses today's anchor log store (ADR-016, `node/anchor.rs`).

### 3.9 Operations

- **R35.** `vox status` **must** show:
  - rooms, peers and their paths (direct or relayed);
  - tunnels and UDP flows;
  - last sync, and anything unhealthy.
- **R36.** Every failure **must** be logged with a specific cause.
- **R37.** Unhealthy rooms or anchors **must** raise a desktop or phone notification.
- **R38.** A metrics endpoint **must** expose node health for dashboards.
- **R39.** Updates stay manual (`vox update`).

### 3.10 Performance targets

- **R40.** A chat message between two online nodes **must** arrive in **under 1 s**, whether direct or
  relayed.
- **R41.** A tunnel on a direct path **must** run near line rate: over the same network link, a Vox
  tunnel **must** deliver at least **90%** of what raw TCP gets at 1 Gbit/s, and is measured and
  reported at other link classes. *Clarified by the decider, 2026-09-25:* "let's not be overly
  pedantic… figure out what the maximum throughput is for a network connection and ensure that our
  overlay system doesn't completely nuke that. We want vox to be as fast and efficient as possible…
  Tor hidden services… felt like a 300 bps modem… I really want our solution to be elegant and fast
  and wonderful to use." "Raw" is a real (emulated) link, not loopback TCP.
- **R42.** A first connection to a peer, including NAT traversal, **must** complete in **under 2 s**.

### 3.11 Removals

- **R43.** Deniable mode (ADR-009) **must** be removed from the code. The ADR keeps the design.
- **R44.** The withdrawn capability model **must** be removed everywhere it survives, including IPC
  `T_GRANT`.
- **R45.** The rate quota **must** be removed (R3), and so must the anchor log store (R34).

## 4. Shipped defects to fix first

Read in code on v0.2.7. Each is fixed only when a shipped-binary gate proves it, and a mutation check
shows that gate going red on the defect.

| # | Defect | Requirement | Where |
|---|---|---|---|
| D1 | A room cannot reopen after one author's 1,000th entry: reload re-applies the rate quota | R1, R3 | `node/channel.rs:868`, `log/dag.rs:380` |
| D2 | An unbounded `WANT` range wedges a room | R4 | `log/sync.rs:450` |
| D3 | Remote urgent messages never wake an agent; `tail` never shows remote messages; `interrupt_proof` never runs the daemon | R16 | `node/actor.rs:4821`, `vox-tui/src/app.rs:806` |
| D4 | `vox room get` writes to a path the sender chooses, and deletes the file on a hash mismatch | R18 | `vox-tui/src/room_cli.rs:822` |
| D5 | Sync serves any room to a member of any other room held by this node | R5 | `node/network.rs:468`, `node/actor.rs:4030` |
| D6 | SOCKS reports "succeeded" before dialling | R23 | `node/up.rs:268` |
| D7 | `vox forward` pins one connection for its whole life | R24 | `node/tunnel.rs:217` |
| D8 | A 30 s accept serialisation blocks the next connection | R42 | `node/actor.rs:736` |
| D9 | The drain hook lets one author forge another's lines | R19 | `vox-tui/src/agent_hook.rs:110` |
| D11 | An abortive close arrives as a clean EOF | R22/R23 | `tunnel/session.rs:336, 374` |
| D12 | IPC `T_GRANT` writes withdrawn capabilities | R44 | `node/ipc.rs:137` |

(D10, agent loop control, is out of scope under R3.)

## 5. Order of work

1. **Fix the shipped defects** in §4.
2. **Build the datagram seam and UDP tunnels** (R25–R27). The seam is:
   - flow-addressed datagrams bound to a stream;
   - a datagram router per connection;
   - relays that carry datagrams;
   - fragmentation.
3. **Build the app API** on the same seam (R29–R30); the chat/calls app builds on this.
4. **Naming** (R20).
5. **Retention, ordering, offline keys and history** (R6–R14).
6. **The family LAN** (R28), once UDP forwarding is proven.

Operations (R35–R38) and the performance gates (R40–R42) land alongside each step, not at the end.

## 6. ADR impact

| ADR | Change |
|---|---|
| 006 Group messaging | Offline key delivery via member nodes, per-grant history, key deletion |
| 008 Replicated log | Remove the quota; bound `WANT`; per-room sync gate; total order; retention and pruned payloads |
| 009 Deniability | **Withdrawn**; code removed, design kept |
| 010 At-rest | Room and node retention, shortest wins; the stale "no persistence layer" note |
| 012/016 Reachability / node runtime | Anchors store nothing for non-member rooms; <2 s first connect |
| 013 Tunneling | UDP over datagrams with fragmentation; relay datagram carriage; family LAN (TUN) back in scope |
| 017 Room-bound services | Local naming `node.room.vox`; teardown on service removal; honest refusals |
| 020 Agent comms | Fingerprint addressing; remote wake; claim rules; `vox share` pull; remove §9 wiring from scope |
| 021 Work-item interop | Hard-lock marking and the handoff window for claims |
| **New** | App stream and datagram API (the calls foundation) |

## 7. Open questions for the ADRs

1. **Skeleton growth.** Rooms are unbounded and expired messages keep their skeleton, so skeletons grow
   forever with about 500 members. Is that acceptable, or should very old skeletons compact into a
   signed checkpoint?
2. **Total order.** Which tie-break for concurrent messages: hash, or fingerprint then sequence? And what
   does a late-arriving message do to the order already shown?
3. **Retroactive retention vs work items.** Does a disappearing-messages room also expire claims and work
   items?
4. **Handoff window.** What is the default, and who sets it: the filer, the room or the node?
5. **Hard lock.** Should a hard-locked claim wait for certainty (block until settled) rather than be
   tentative?
6. **Naming collisions.** Two rooms I've both nicknamed `family`, or a node name that isn't in my keyring:
   refuse, or disambiguate?
7. **No always-on member.** In a room with no always-on member, two nodes that are never online together
   cannot exchange keys (a consequence of R11 + R34). Accept this, or require an always-on member?
8. **Fragmentation.** Where does it happen (per flow, per datagram), and what is the loss budget before a
   fragmented packet is dropped?
9. **Removing the quota.** Is a per-node storage cap still wanted to protect disks, now that the rate
   quota is gone?
