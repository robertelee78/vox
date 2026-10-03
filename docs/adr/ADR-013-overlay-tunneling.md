# ADR-013: Overlay Tunneling (TCP-over-Vox)

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted.

Built on integrate/v0.3.0:
- the per-stream port-forward and SOCKS5 models (`crates/vox-core/src/{tunnel,node/tunnel,node/up}.rs`;
  `vox serve`, `vox service`, `vox forward`, `vox up`, `vox tunnel close`);
- UDP services (ADR-022);
- the per-member tunnel cap and tunnel listing;
- closing stuck tunnels.

Built and not yet proved: the family LAN's macOS `utun` path, which needs the decider's root run.

Not built: the general TUN model, the family LAN on Linux, signed tunnel-session events,
audience-sealed service advertisements, and tunnel stream priority. Requirements say which.

**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: tunneling, tcp, udp, socks, tun, lan, authorization

## Context

Tunneling is a first-class Vox capability (ADR-001): the overlay carries TCP and UDP between room
members, with `ssh` over Vox as the canonical use. It runs on the per-peer QUIC connection
(ADR-011), reaches peers through ADR-012's ladder, and is authorized by the host's own approval of a
member's key (ADR-017 decision 3, revised 2026-09-21).

The model is Tor's hidden service: the overlay decides **reach**, and the carried service decides
**who its users are**. A room-bound service does not bring an authentication scheme of its own.

## Requirements

### Interface models

- **T-1. Per-stream forward and SOCKS, primary.**
  - A node MUST offer `vox forward <service>.<node>.<room>.vox [<local>]`, which forwards one local
    port to the service that address names, and
    `vox up`, a SOCKS5 proxy that resolves `.vox` names (ADR-017 decision 5). Only
    `service.node.room.vox` connects; `node.room.vox` and `room.vox` resolve to nothing (ADR-017).
  - Both MUST work without privilege.
  - The port in a `.vox` request is a Vox-layer identifier that the host MUST translate to the local
    endpoint it declared. It binds nothing on the host.
- **T-2. TUN, optional.** A TUN virtual interface MAY be offered. Per-service authorization MUST
  still apply on that path. Its datapath (a privileged helper or `NetworkExtension`, and a userspace
  TCP stack) belongs to the client (ADR-014), not to `vox-core`; the family LAN's engine is the one
  exception, because both ends of it are real kernels and it needs no userspace TCP stack. Status:
  not built, except the family LAN (T-21 to T-27). Its addressing is defined in T-28.

### Authorization

- **T-3.** A service MUST be dark by default. It MUST be reachable only by a member the host has
  approved, and MUST NOT be an open port reachable by topology.
- **T-4. Reach is the host's approval.** A service a host bound to a room MUST be reachable by
  exactly the members of that room whose keys that host has approved for reading (`reachers`,
  enforced in `tunnel::session::accept`). In particular:
  - approving a reader MUST confer reach on every service that host bound to that room, at once and
    with no second act;
  - withdrawing approval, or Block, MUST withdraw reach at once, MUST reset that member's live
    tunnels with `REACH_WITHDRAWN_CODE` (`0x1711`), and MUST tell the far end why (ADR-017
    decision 10);
  - there MUST be no state in which a member is blocked in chat yet keeps a tunnel, and none in which
    a tunnel is revoked while chat readability continues.
- **T-5. Membership grants no reach.** Joining a room, holding its passphrase, or paying its proof
  of work MUST confer no tunnel reach by itself. Reach MUST NOT be inherited from membership. A
  member the host has not approved MUST NOT be able to reach, enumerate, or learn of any service.
- **T-6.** No per-member capability grant exists. There is no `vox grant`, no `GrantTunnel`
  command, and no IPC tag 10. IPC tag 10 (`T_GRANT`) MUST NOT be reused. Reach cannot be narrowed
  below "this host's approved readers in this room" or extended to a non-member (ADR-017
  decision 3).
- **T-7. Offering a service is configuration, not authorization.** A host MUST be able to offer a
  port of its own machine in a room without any capability check. Offered services MUST persist in
  the room's sealed store (`SEG_SERVICES`), at most `MAX_SERVICES` (64) per room.
- **T-8. Advertisements.** A service advertisement MUST NOT be posted as cleartext on the replicated
  log (ADR-008). If advertised, it MUST be sealed to exactly the host's explicitly approved readers in
  that room (ADR-017, third revision: consent-bound services), per recipient like an SKDM (ADR-006),
  as a `ServiceAdvertisement` (ADR-008 tag `0x000F`), delivered over each reader's pairwise channel
  (ADR-004) or as a log entry sealed to that audience. A member the host has not approved MUST NOT be
  able to read one. A requester MUST resolve a service only by decrypting the advertisements it can
  open; there is no responder-side filter. When the approved readers change, the host MUST re-seal
  and re-publish its advertisement. Status: the struct and the sealing exist in `tunnel::service` with no caller. A
  member learns another's service tags out of band, and closing that is ADR-017 M17.4.
- **T-9. Accountability.** Tunnel session establishment SHOULD be recorded as a signed event in
  attributable rooms (ADR-009). Status: not built; no entry type exists.
- **T-10. SSH certificate authority, optional.** A Vox-issued OpenSSH certificate authority MAY be
  built later, under its own ADR. It is not a requirement here. `tunnel::sshca` is an unwired seam.
  "`ssh` over Vox" means forwarding to a real `sshd`, which authenticates its users as it always does.
  **Known gaps of the seam,** for that future ADR to close: no binding to the capability tree;
  `verify_user_cert` ignores extensions and critical options; the capability is carried as an
  extension rather than a critical option.

### The tunnel stream

- **T-11.** Each tunneled TCP connection MUST get its own QUIC stream (`StreamKind::Tunnel`), so
  that tunnels never suffer head-of-line blocking from messaging, sync or each other. Backpressure
  MUST come from QUIC per-stream flow control. Interactive tunnel streams SHOULD be prioritized, and
  genuinely bulk transfers SHOULD use separate streams, or separate connections for true QoS
  (ADR-011). Status: priority is planned, not built; nothing on the tunnel path sets a stream
  priority.
- **T-12. UDP.** A UDP service MUST be tunneled as `udp/<name>`: a datagram flow bound to its tunnel
  stream after the same gate (ADR-022 decision 6, M22.3/M22.4). This covers `vox serve dns=53/udp`,
  `vox forward dns.<node>.<room>.vox [<local>]` and SOCKS5 `UDP ASSOCIATE` in `vox up`.
- **T-13. The request names its room (M16.1).** A tunnel request MUST be `[channel_id, service_tag]`,
  and the host MUST resolve services per `(room, tag)`. A host MUST answer an unauthorized peer, an
  unknown room, an unknown service and a failed local connect with the same `TunnelStatus::Denied`,
  so that a refusal reveals nothing. `TunnelStatus::Full` (T-15) is the one distinct answer.
- **T-14. A tunnel lives off the actor.** A host MUST serve each tunnel against a snapshot of the
  rooms' reachers and offered services, so that a long-lived tunnel never reaches back into the actor.

### Limits and closing

- **T-15. Per-member cap (#272).** A node MUST carry at most `TUNNELS_PER_PEER` (16) live tunnels
  per member. Past the cap, a new tunnel MUST be refused (`TunnelStatus::Full`) with a reason that
  says how to free one: `vox tunnel close`, closing the program using it, restarting the `vox up` or
  `vox forward` carrying it, or on the host `vox service remove` or `vox trust remove`.
- **T-16. Listing.** `vox status` MUST list every live tunnel with its number, member, service, when
  it opened and when it last moved.
- **T-17. Closing (V030-11).** A person MUST be able to close a tunnel with `vox tunnel close` (by
  member, by member and service, or by number) and from the TUI. The far end MUST be told it was
  closed (`TUNNEL_CLOSED_CODE`, `0x1713`).
- **T-18. Stuck tunnels (V030-11).** A tunnel whose bytes have waited `STUCK_AFTER` (10 min, or the
  profile's `tunnel-stuck-after`, under ADR-026 the node's `config`) for the far end or the local application to take them MUST be closed
  as stuck (`TUNNEL_STUCK_CODE`, `0x1714`). An idle tunnel with nothing waiting MUST NOT be closed.

### Honesty (PRD-001 R22–R24)

- **T-19.**
  - **SOCKS replies.** `vox up` MUST reply only after the host answers: `NotAllowed` for a host
    refusal, `GeneralFailure` for an unreachable host. It MUST print the reason on the operator's
    terminal (`NodeEvent::ProxyRefused`).
  - **Refused forwards.** A refused `vox forward` connection MUST reset the application's socket and
    print the reason.
  - **Abortive close.** A TCP error on either end MUST reset the QUIC stream with
    `TUNNEL_ABORT_CODE` (`0x1712`). A reset arriving from the far end MUST close the local socket with
    zero linger, so the kernel sends RST.
  - **Removed services.** Removing a service MUST cut its live sessions. `vox service remove` MUST
    reach the running node when one holds the profile. *Decided, not built (ADR-026 S-3):* every
    tunnel verb (`serve`, `connect`, `up`, `forward`, `service`) is a client of the account's daemon,
    acting as the node it resolves; tunnels, counters and closes are per node, and one node cannot
    list or close another's tunnel.
  - **Host restarts.** A forward MUST reach its host afresh for each accepted connection
    (`up::open_tunnel`). It MUST retry a path failure within `HOST_PATIENCE` (300 s), MUST NOT retry a
    refusal, and MUST back off a failed accept (`ACCEPT_BACKOFF`) rather than end or spin.
  - **Patience at start.** `vox forward` MUST wait for its host with `HOST_PATIENCE`, as `vox up`
    does, printing each attempt's rung verdicts.
  - **A restarted host.** A running `vox forward`'s and `vox up`'s first connection after their host
    restarts MUST reach the new process within V210-57's 10 s host-restart bound. Status: planned,
    until #360 (V210-141) and #321 merge. **Known limit until then:** the first connection after a
    host restart can wait out QUIC's idle timeout on the dialer's stale connection, about 60 s;
    tracked as V210-141 (#360). Note: 1.25–1.26 s was measured on V210-141's unlanded branch
    (`75e110d8`, on #321's unlanded `7fecc49d`), not on either integrate branch, with its proof
    `tunnel_honesty_proof::a_restarted_host_is_reached_again_promptly_by_a_forward_and_by_a_proxy`.

### Loopback

- **T-20.** `vox forward` and `vox up` MUST bind loopback only. A forward's address MUST be checked
  in the actor before anything is dialled (`Fault::NotLoopback`) and again where its socket is created
  (`Forward::bind`). `vox up` MUST drop a peer that is not on loopback. There MUST be no flag to
  override this.

### The family LAN (PRD-001 R28)

Status: proposed. The engine (`vox_core::lan`), the address plan, the packet mapping, the flood
fan-out, the caps and the port whitelist are built and proved without root
(`family_lan_proof`). The macOS `utun` path (`vox lan helper`, `vox lan up`) is built and becomes
proven when the decider runs `sudo scripts/family-lan-proof.sh`. Linux is not built.

- **T-21. What it is.** A room's trusted members MAY share one IP subnet, so that software that
  discovers peers on the local network works across Vox.
- **T-22. Addressing (`lan::plan`).** Every node MUST compute the plan from the room id and member
  list alone:
  - **IPv4:** one /24 of `100.64.0.0/10` (RFC 6598) chosen by the room's hash. Members hold
    `.1`–`.254`, each with a preferred host from its own hash, with collisions settled in a fixed hash
    order that is the same on every node. A member past the 254th gets no IPv4 address. `vox lan up`
    MUST say so when a member is moved from its preferred host.
  - **IPv6:** a per-room RFC 4193 /64 (`fd` ‖ 40 bits of the room's hash), with a 64-bit interface
    id from the member's hash.
- **T-23. Device (macOS).**
  - The device MUST be a `utun` with MTU 1280.
  - Root's part MUST be its own process, `sudo vox lan helper`. It serves only the uid that ran
    `sudo` (`getpeereid`), and accepts only a host in `100.64.0.0/10` and one in `fd00::/8`. It
    creates, addresses and routes the `utun`, and hands the descriptor to `vox lan up` (`SCM_RIGHTS`).
    It MUST keep nothing, open no profile and touch no network. Under ADR-026 it stays its own root
    process and never uses the account's control socket, which does not admit uid 0. The daemon, as
    the same uid, asks the helper for the device and runs the LAN; the user-side `vox lan up` is a
    daemon client holding a session (ADR-026 S-5, L-7).
  - `vox lan up` MUST run as the person.
  - One `sudo vox lan up` that drops privileges MUST NOT be used: macOS keeps root's supplementary
    groups unless `setgroups` runs, and no safe binding offers it.
- **T-24. Linux.** Linux MUST use `/dev/net/tun`. Status: not built, because `TUNSETIFF` has no safe
  wrapper. Building it needs either an `unsafe` exception or a crate that does the ioctl, and that is
  the decider's call.
- **T-25. Unicast and broadcast.**
  - **Unicast** MUST ride the app API (ADR-022 decision 7), label `vox-lan/v1`: one app stream per
    trusted member with a datagram flow bound, and one IP packet per datagram. The gate MUST be the app
    gate, checked on both ends and withdrawn live. When both ends open at once, both MUST keep the
    stream the lower fingerprint opened.
  - **Broadcast and multicast** (`224.0.0.0/4`, the subnet broadcast, `255.255.255.255`,
    `ff00::/8`) MUST be copied onto every admitted link, and only those. An arriving subnet broadcast
    MUST be rewritten to `255.255.255.255`, with the IPv4 and UDP checksums fixed.
- **T-26. Caps and checks.**
  - Floods MUST be token-bucketed both ways: what this node floods, and what each peer may flood into
    it. The rate is `FLOOD_RATE` (100 a second) with bursts of `FLOOD_BURST` (200).
  - The receiver MUST check that the source is an address of the member it came from and that the
    destination is one of its own addresses or a group. Packets that fail MUST be dropped, so a member
    can impersonate nobody and cannot use a node as a router. IPv6 discovery from a link-local source
    is therefore dropped.
- **T-27. Ports: a whitelist, default none (decider, 2026-09-25).** `vox lan up <room> --allow
  <ports>` MUST name the reachable ports. With no `--allow`, every port on the machine MUST be
  unreachable over the LAN, while discovery still flows. The receiving node MUST enforce it before a packet
  reaches the `utun` (`lan::admitted`):
  - a TCP SYN without ACK passes only to a listed port, and other TCP segments pass;
  - UDP passes to a listed port, or as a reply to a local port this node sent from within
    `UDP_REPLY_WINDOW` (120 s), from the address it sent to, or from anyone after a group send;
  - ICMP passes;
  - broadcast and multicast pass on any port, under the caps;
  - anything whose ports cannot be read is dropped.

### Addressing for the TUN model

- **T-28.** A member's TUN address MUST be `0xFD ‖ high-120-bits(SHA-256("vox/ula/v1" ‖
  composite_identity_pubkey))`, a self-certifying /128 that a peer verifies by recomputing it. It is
  not RFC 4193 addressing and MUST NOT be expected to interoperate with other ULA users on a link. An
  address MUST confer no reach. Status: `tunnel::addr` exists with no caller (T-2).

### Verbs

- **T-29.**
  - `vox forward` MUST bind its local port before it dials, so that a port already in use is an error
    the person sees.
  - Dropping a forward MUST stop its listener and MUST leave connections already spliced to finish.
  - Room and member ids MAY be given as unique prefixes of their base32 rendering; an ambiguous
    prefix MUST be refused with a count, never guessed.
  - Passphrases MUST be read without echo on a terminal, or from a pipe when stdin is not a terminal,
    so that nothing lands in shell history.

## Consequences

- One overlay carries private chat and least-privilege tunnels, with reach and readability on one
  axis that a person controls with one act.
- Reach cannot be narrowed below "this host's approved readers in this room".
- A TUN path, general or LAN, needs root and real platform security review.
- Carrying interactive TCP raises the bar on connectivity quality (ADR-011, ADR-012).

## Related ADRs

ADR-001 (scope), ADR-002 (identity), ADR-006 (sender keys), ADR-007 (consent), ADR-008 (log and
tags), ADR-009 (attribution), ADR-011 (transport), ADR-012 (reachability), ADR-014 (macOS client),
ADR-017 (room-bound services), ADR-022 (datagram flows and the app API).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
