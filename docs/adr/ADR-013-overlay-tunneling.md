# ADR-013: Overlay Tunneling (TCP-over-Vox)

**Status**: implemented and **reachable** — the per-stream port-forward model runs end to end through the node (`crates/vox-core/src/{tunnel,node/tunnel}.rs`, `crates/vox-tui` `service`/`grant`/`forward`), gated by a release test that reaches a TCP service between two symmetric-NAT clients through an anchor; SOCKS front-end, signed session events, the SSH-CA binding and the TUN datapath remain (see Known gaps)
**Date**: 2026-06-19
**Updated**: 2026-09-25 — **the family LAN is proposed and partly built** (PRD-001 R28, "The family LAN" under
Interface models). The engine, the address plan and the gate are proven without root. The macOS `utun` path is built and
waits for the decider's sudo proof. Linux is designed only. 2026-09-24 — **UDP services are tunneled** as `udp/<port>`, a datagram flow bound to the tunnel stream after the same gate (ADR-022 decision 6, M22.3/M22.4: `vox serve 53/udp`, `vox forward <name>.vox 53/udp <port>`, SOCKS5 `UDP ASSOCIATE` in `vox up`); see ADR-022 for the proofs. 2026-09-24 — **a tunnel tells the truth about how it ended** (PRD-001 R22–R24): a SOCKS reply is the host's answer, a refused or cut forward resets the application's socket, an abortive close is carried as one, removing a service cuts its live sessions, and a forward reaches its host afresh per connection; `tunnel::authz`, `grant_capabilities`, `NodeCommand::GrantTunnel`, IPC `T_GRANT` and the `vox grant` verb are removed. See "Tunnel honesty" under Implementation notes. 2026-09-21 (later the same day) — **tunnel authorization is per-sender consent, not a per-member capability.** ADR-017's third revision withdraws the genesis service grant, `0x0013` and `vox grant`; this ADR's invariant that *"tunnel capabilities are never inherited from membership"* is restored **unqualified**, and its claim that message consent and tunnel access are *orthogonal* is **reversed** — they are one axis. See the Authorization model bullets and the `node_m15_anchor_gate` note. 2026-09-21 — the **SOCKS5 front-end is built and is the person-facing entry point** (`node::up`, ADR-017 decision 5 / M17.3): it resolves `.vox` names and needs no privilege, which is what this ADR listed as primary from the start. The TUN model stays optional and unbuilt. (A brief revision promoting TUN to the primary path was reverted the same day — see ADR-017 decision 5.) 2026-09-19 — status reconciled; Known gaps recorded. 2026-09-21 — the **SSH certificate authority is narrowed to an optional later capability** (decider, see the note below); the per-stream port-forward model is the specified one, and the person-facing surface moves to ADR-017 (room-bound services). 2026-09-20 — the tunnel request names its channel and capabilities are issued as log facts (M16.1a); the node serves tunnels, offers services and forwards ports, with the `vox service` / `vox grant` / `vox forward` verbs (M16.1b) — Status updated to match.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: tunneling, tcp, ssh, tun, socks, authorization, zero-trust

## Context

Tunneling is a first-class Vox Lux capability, not an add-on (ADR-001): the overlay carries
arbitrary TCP/IP between channel members, with `ssh` over Vox as the canonical use case. The
substrate is decided — QUIC connection per peer with stream multiplexing + RFC 9221 datagrams
(ADR-011), NAT traversal with user-runnable rendezvous (ADR-012) — and authorization must reuse
identity (ADR-002) and the membership / per-sender consent / signed admin certificate tree
(ADR-007). Research is authoritative on the **authorization model** (OpenZiti, Tailscale, SSH CA);
the interface, addressing, stream-mapping, and Rust-component choices are designed from the
established substrate and marked as such. This ADR specifies the complete tunneling capability.

## Decision

### Interface models — offer both, mapped onto QUIC streams (ADR-011)

- **Per-stream SOCKS / port-forward (ssh-style) — primary.** Targeted, least-privilege: expose a local
  SOCKS proxy that resolves `.vox` names and carries what it is asked for (`vox up`, ADR-017 decision 5,
  built 2026-09-21 as `node::up`), or forward a single local port to a specific member's service
  (`vox forward`). This is the default and the path for `ssh` over Vox, and it is the shape Tor uses for
  the same reason: it needs no privilege of any kind. The port in a `.vox` request is a Vox-layer
  identifier that the serving side translates to whatever local endpoint it declared, the way a NAT does
  — so it binds nothing and collides with nothing the host already runs.
- **TUN virtual interface (VPN-style) — optional, and not built.** A `utun` interface with
  identity-derived addressing for "everything just routes" between members; on macOS via
  `NetworkExtension` / privileged helper (notarized, ADR-014). It is the only way an *unmodified* tool
  reaches a name with nothing configured, which is why it stays specified — but it is an addition, not the
  path, exactly as Tor's `TransPort` is. Per-service authorization (below) still applies on the TUN path
  — the interface is convenience, not a bypass of policy. *(A userspace stack for this was built and
  removed on 2026-09-21; see ADR-017 decision 5's recorded reversal for why.)* One room-scoped form of
  it is now specified and partly built: **the family LAN**, next.

### The family LAN (PRD-001 R28) — proposed, 2026-09-25

**Status: proposed.** Built and proven without root: the address plan, the packet mapping, the flood
fan-out, the caps and the gate (`family_lan_proof::a_room_is_a_lan_for_its_trusted_members_and_nobody_else`,
four real nodes, the kernel replaced by channels; green 4 of 4 runs in release). Each property was
mutation-checked, and each mutation went red on its own assertion:
  - flooding to one link: bob got 0 of 10 mDNS packets;
  - routing to the wrong link: 100 of 202 unicast packets arrived;
  - dropping the source check: 2 spoofed packets were delivered;
  - removing the caps: 1000 floods delivered, against a bound of 201;
  - no broadcast rewrite, or no UDP checksum fix: 0 of 10 were right.

  Removing the responder's app gate alone stayed shut, because the live guardian tore carol's stream down.
  Removing the gate and the guardian together let carol link. Built and **not yet proven**:
the macOS `utun` path (`vox lan helper`, `vox lan up`) — that needs root, and is proven only when the
decider runs `sudo scripts/family-lan-proof.sh`. Linux is designed, not built (below).

- **What it is.** A room's trusted members on one IP subnet, so software that discovers things by asking
  the local network — Plex/Jellyfin, Chromecast, a game's LAN lobby — works across Vox. Engine:
  `vox_core::lan`; CLI: `crates/vox-tui/src/lan_cli.rs`.
- **Addressing** (`lan::plan`), computed by every node from the room id and its member list alone:
  - **IPv4:** one /24 of `100.64.0.0/10` (RFC 6598: neither public nor a home router's RFC 1918) chosen by
    the room's hash; members hold `.1`–`.254`. A /24 is too small for hashing alone (ten members collide
    about one time in six), so each member has a preferred host from its own hash and collisions settle in
    a fixed hash order, the same on every node. A later joiner can move a member whose preferred host was
    taken; `vox lan up` says so. A member past the 254th gets no IPv4 address. Tailscale uses the same
    range; a clash shows as an existing route.
  - **IPv6:** an RFC 4193 /64 per room (`fd` ‖ 40 bits of the room's hash), with a 64-bit interface id from
    the member's hash. Per room, not the per-identity `fd…/128` below: a LAN needs a shared on-link prefix,
    and per-room addresses do not link one person's presence across rooms.
- **Device.** macOS `utun`, MTU 1280. Creating and addressing one needs root, so root's part is its own
  process, **`sudo vox lan helper`**, which serves only the uid that ran `sudo` (`getpeereid`), accepts only
  a host in `100.64.0.0/10` and one in `fd00::/8`, creates the `utun`, addresses it, routes the /24 and /64
  to it, and hands the descriptor to `vox lan up` over its socket (`SCM_RIGHTS`). It keeps nothing, opens
  no profile and touches no network. `vox lan up <room>` runs **as the person**. The kernel destroys a
  `utun`, with its addresses and routes, when the last descriptor closes, so the interface lives exactly as
  long as `vox lan up`, crash included. *Rejected:* one `sudo vox lan up` that drops privileges. macOS keeps
  root's supplementary groups (`admin`, `kmem`) across `setuid` unless `setgroups` runs, and no safe binding
  offers `setgroups` on Apple targets. **Linux** must use `/dev/net/tun`, whose `TUNSETIFF` ioctl has no
  safe wrapper. Building it needs either an `unsafe` exception or a crate that does the ioctl; that is the
  decider's call.
- **Unicast** rides the app API (ADR-022 decision 7), label `vox-lan/v1`: **one app stream per trusted
  member with a datagram flow bound**, one IP packet per datagram (fragmented by the flow past the path's
  datagram size). The gate is the app gate, unchanged: this node's keyring joined with the room's authors,
  checked on both ends, withdrawn live. When both ends open at once, both keep the stream the lower
  fingerprint opened. **TCP** inside the LAN needs nothing: its segments are packets, and the endpoints'
  TCP stacks retransmit what a datagram loses. No userspace TCP stack is needed, unlike the TUN model above,
  because both ends are real kernels.
- **Broadcast and multicast** (`224.0.0.0/4` including mDNS `224.0.0.251` and SSDP `239.255.255.250`, the
  subnet broadcast, `255.255.255.255`, `ff00::/8`) are **copied onto every link**, as a switch floods. A copy
  goes only where the gate admitted a link, so an untrusted member receives nothing. A `utun` is
  point-to-point and does not accept its subnet's broadcast address, so an arriving subnet broadcast is
  rewritten to `255.255.255.255`, fixing both the IPv4 and the UDP checksums.
- **Caps.** A flood costs one datagram per member and is unasked-for, so both directions have a token
  bucket: what this node floods, and what each peer may flood into it, 100 a second with bursts of 200.
- **Checked on arrival, at the receiver** (the side whose code the sender does not control): the source
  must be an address of the member it came from, and the destination one of mine or a group. So a trusted
  member can impersonate nobody and cannot use a node as a router. The cost: IPv6 discovery sourced from a
  link-local address (`fe80::`) is dropped, so mDNS over IPv6 does not cross, and mDNS over IPv4 does.
- **Ports: a whitelist, default none (decider, 2026-09-25).** Without it, `vox lan up` would expose every socket
  bound to the wildcard address to every trusted member, which is wider than `vox serve`. So
  `vox lan up <room> --allow 32400,8009,…` names the reachable ports. With no `--allow`, **nothing on the machine is
  reachable over the LAN**, and discovery still flows. It is enforced **on the receiving node, before a packet reaches
  the utun** (`lan::admitted`):
  - a TCP SYN (without ACK) passes only to a listed port. Other TCP segments pass: they belong to a connection that
    exists, or the kernel resets them;
  - UDP passes to a listed port, or as a reply:
    - to a local port this node sent from within 120 s;
    - from the address it sent to, or from anyone if it sent to a group (an SSDP search is answered by unicast);
  - ICMP passes;
  - broadcast and multicast pass on any port, capped: they are the discovery;
  - anything whose ports cannot be read is dropped: other protocols, later fragments, IPv6 extension headers.

  Proven in `family_lan_proof` (phase 9, green 3 of 3 in release):
  - every member allows only 5000, and the floods go to unlisted 5353, 1900 and 9999 and still cross;
  - UDP and a SYN to an unlisted port deliver 0;
  - a SYN to a listed port delivers 1, and so does a non-SYN to an unlisted port;
  - replies after a unicast send and after a group send are each delivered;
  - UDP to a port never sent from delivers 0.

  Mutations, both red:
  - whitelist bypassed: 10 of 10 delivered to the unlisted port;
  - reply tracking off: both replies 0.

### Authorization model (evidence-driven): zero-trust, capability-scoped, consent-gated

- **Dark services, default-deny.** A tunnelable service is never an open listening port reachable by
  topology; it is a logical service reachable only by a member holding a valid grant, enforced
  cryptographically at QUIC session/stream setup. No inbound open ports.
- **Bind vs Dial are distinct rights** (OpenZiti model): *advertise/host* (Bind) and
  *consume/connect* (Dial) are separate capabilities granted independently per member per service.
  Hosting an ssh port requires Bind; connecting requires Dial; neither implies the other.
- **ABAC over signed role attributes, evaluated by the ADR-007 evaluator (no parallel engine).** Bind/
  Dial and role tags are **capabilities registered in the ADR-007 lattice** (`bind:<service-tag>`,
  `dial:<service-tag>`, attenuable role attributes like `#ops`/`#ssh-hosts`), issued as signed
  capability certificates chaining to genesis (ADR-007). A policy like "members tagged `#ops` may Dial
  `#ssh-hosts`" is decided by the **single deterministic ADR-007 evaluator** over those grants — ADR-013
  introduces no second authorization engine, so the one golden-vector suite covers tunnel authz too.
- **Authorization gates discovery — and advertisements never sit in cleartext on the shared log.**
  Because the replicated log (ADR-008) delivers every entry to every member, a service advertisement
  is **not** posted as cleartext channel content (doing so would make discovery-gating illusory).
  Instead a Bind holder distributes its advertisement **only to members holding the matching Dial
  capability** — either over their authenticated pairwise channels (ADR-004) or as a log entry
  **encrypted to that authorized audience** (the Dial-grant set, keyed like a per-recipient SKDM,
  ADR-006). A member can thus enumerate only the services it is authorized to consume; an
  unauthorized member sees at most opaque ciphertext and cannot even learn a service exists. This
  resolves the otherwise-contradiction between discovery-gating and the replicate-all log.
- **~~Membership grants tunnel reach only where an immutable genesis says so.~~ Withdrawn 2026-09-21.**
  The qualification added earlier that day — ADR-017 decision 3's genesis **service grant**, conferring
  `dial:`/`bind:` on every admitted member of a room that declared one — is **withdrawn in full**, along
  with its `service-grant-exclusion` (`0x0013`). Admission to a room is a passphrase and a proof of work,
  not a human decision, so a grant keyed to membership made every syncing peer's admitted-author set into
  an access control decision nobody took. The invariant below therefore stands **unqualified** again, which
  is how it was written. Authorization is instead the host's per-sender consent (next bullet but one, and
  ADR-017 decision 3 as revised).
- **Chat membership grants NO tunnel reach — this is a hard invariant (but the two coexist freely in one
  swarm).** Joining a channel, holding the passphrase, or being consented-to for *messages* conveys
  **zero** tunnel reachability *by itself*. Tunnel capabilities are **never inherited from membership** —
  reach follows the **host's own per-sender approval of that member's key**, which is a deliberate human
  act and is not membership (ADR-017 decision 3, revised 2026-09-21). A **single swarm can absolutely
  carry both comms and tunnels at once** (the compute-node case: one channel carries chat and services,
  and each host serves the members it has approved); what is forbidden is *automatic* tunnel access
  falling out of chat membership. So the "here, join my chat" → "now I'm on your LAN" path is
  structurally impossible: a joiner the host has not approved cannot enumerate or reach any service
  (dark services, default-deny, above) and cannot learn one exists, even holding the passphrase and a
  valid ULA address — while a teammate the host *has* approved reaches the services that host bound to
  that room, and nothing more.
- **Tunnel authorization *is* message consent — one axis, not two (revised 2026-09-21).** This bullet
  previously held the opposite, and the reversal is the substance of ADR-017's third revision, so the old
  text is quoted rather than deleted: *"Revoking per-sender message consent / Block (ADR-007) does NOT
  touch tunnel access, and vice-versa — the two axes are independent."* **That is withdrawn.** A service a
  host bound to a room is reachable by exactly the members of that room whose keys that host has approved
  for reading, so:
  - approving a reader confers reach on every service that host has bound to that room, **immediately and
    with no second act**;
  - withdrawing consent / Block withdraws reach in the same instant, tears down that member's live streams
    and reports the reason to the far end (ADR-017 decision 10);
  - there is no state in which a member is blocked in chat yet retains a tunnel, and none in which a
    tunnel is revoked while chat readability continues.

  Two surfaces that could disagree with each other were the bug class behind two verified findings; one
  surface cannot. The cost is that reach can no longer be narrowed below "this host's approved readers in
  this room", nor extended to a non-member at all — both stated and accepted in ADR-017 decision 3.
- **SSH-CA mapping (concrete).** "ssh over Vox" uses the member's verified Vox identity (ADR-002) as
  the authority. Vox issues a standard **OpenSSH certificate** with this field mapping: `key_id` = the
  Vox identity fingerprint; `valid_principals` = the granted role/service tags used **verbatim** as principals (the `#`-prefixed
  tag string, no transformation — e.g. `#ops` is the principal `#ops`, not `ops`);
  `critical_options`/`extensions` carry the governing Vox capability (`dial:<service>`); `valid_after/
  before` = a short window (**default 5 min**). It is signed by the **channel SSH-CA key**, which is an
  `admin`-delegated capability cert in the ADR-007 tree. The SSH host trusts that CA pubkey via an
  `@cert-authority` line (delivered as a channel entry), so there is **no host-key TOFU** — the host's
  identity is the verified Vox identity.

### Addressing & name resolution

- **Identity-derived addressing (concrete derivation).** For the TUN model, each member's address is
  `addr = 0xFD ‖ high-120-bits( SHA-256("vox/ula/v1" ‖ composite_identity_pubkey) )` — a self-certifying
  /128 in the `fd00::/8` range (CGA/Yggdrasil-style). It is unforgeable (bound to the key), needs no
  allocation, and a peer **verifies** an address by recomputing it from the claimed identity; 128-bit
  output makes collision negligible. **This is intentionally *not* RFC-4193-conformant ULA addressing**
  (no 40-bit pseudo-random Global ID + 16-bit subnet structure) — it is Vox-CGA-style and must not be
  expected to interoperate with other ULA users sharing a link. **An address grants no reachability** —
  services are dark/default-deny and capability-gated (above); holding a ULA address ≠ being able to
  reach anything. For the SOCKS/forward model, services are addressed logically by
  `(member identity, service name)`.
- **Channel-scoped resolution (single mechanism, consistent with discovery-gating above).** A service
  advertisement is an **audience-encrypted log entry**: an inner signed record — the **`service-advertisement`
  struct (ADR-008 tag `0x000F`, domain `vox/service-ad/v1`, body `{ member_id, service_tag, endpoint }`)** —
  sealed to the current Dial-grant set (keyed per-recipient like an SKDM, ADR-006) and carried as an opaque
  payload on the replicate-all log (ADR-008). A requester resolves a name purely
  by **locally decrypting** the ads it is authorized for; it cannot read or even enumerate ads for
  Dial sets it is not in. There is **no responder-side "filter per requester"** (the log has no
  responder). On a Dial-set change (grant/revoke, ADR-007) the advertiser re-publishes a re-sealed ad.

### Mapping onto QUIC (ADR-011)

- **One QUIC stream per tunneled TCP connection** (ordered, reliable), isolated from messaging and
  bulk-sync streams so interactive tunnels never suffer cross-stream head-of-line blocking.
- **UDP tunneling via QUIC datagrams** (RFC 9221) where unreliable/unordered is appropriate.
- **Backpressure** via QUIC per-stream flow control; interactive tunnel streams are prioritized, and
  genuinely bulk transfers use separate streams (or separate connections for true QoS) per ADR-011.

### Security model

- Least-privilege per stream; capability-scoped (Bind/Dial per service); deny-by-default.
- A malicious member is confined to services explicitly granted to them and cannot enumerate or
  reach others — no lateral movement to un-granted ports/hosts.
- Tunnel session establishment is recorded as signed events for accountability in attributable
  channels (ADR-009); nothing is exposed without an explicit Bind + grant by the host.

### UX / CLI

- `vox service add ssh tcp/22 --grant '#ops'` — advertise a service with a Bind + grant.
- `vox forward <member>/ssh 22` then `ssh -p <localport> localhost`, or a local SOCKS proxy with
  `ssh -o ProxyCommand`.
- `vox up` brings up the TUN interface (privileged helper, identity-derived address); ACLs still
  apply. Client surfacing is specified in ADR-014.

### Rust building blocks

`quinn` for QUIC (streams + datagrams); `tun`/`utun` crates for the TUN interface; a SOCKS5
implementation for the proxy path; `smoltcp` for the userspace TCP handling required on the TUN
path; OS sockets for the forward/SOCKS path. (Interface/addressing/stream-mapping/Rust selections
are engineering design from the ADR-011 substrate; the authorization model is research-backed.)

## Consequences

### Positive
- One overlay for private chat and arbitrary, zero-trust tunneling — the differentiated scope.
- Dark-services + Bind/Dial + discovery-gating give a strong, least-privilege security posture that
  reuses the consent/admin machinery already built (ADR-007).
- "ssh over Vox" drops SSH host-key TOFU in favor of verified Vox identity — strictly better trust.

### Negative
- The TUN path needs a privileged helper / NetworkExtension and a userspace TCP stack — real
  platform and security-review surface.
- Carrying live interactive TCP demands the strict low-latency path (ADR-011/012), raising the bar
  on connectivity quality.
- An ABAC policy + capability-cert system is non-trivial to implement correctly and must be audited.

### Neutral
- Mechanically adjacent to ADR-011 transport, but kept separate as its own user-facing capability
  with its own authorization model.

## Implementation notes (M11)

Built in `crates/vox-core/src/tunnel/` — spec and code in lockstep:

- ~~**Authorization reuses the single ADR-007 evaluator** (`tunnel::authz`)~~ — **removed 2026-09-24** with the rest of the withdrawn capability model (ADR-017 decision 3); reach is the host's reacher set, enforced in `session::accept`. As first written: `can_dial`/`can_bind`/`authorize_dial`/`authorize_bind`/`dial_audience` are thin wrappers over `Evaluator::grants(key, Capability::Dial/Bind(tag))`. No second engine — the one golden-vector suite covers tunnel authz. The `Bind`/`Dial`/`Role` capability vocabulary was pre-provisioned in the M6 lattice (`governance::capability`), so M11 only consumes it. Default-deny, Bind≠Dial, and "chat membership grants no tunnel reach" all fall out of consulting only the capability lattice.
- **Discovery-gating by encryption** (`tunnel::service`): `ServiceAdvertisement { member_id, service_tag, endpoint }` is a composite-signed struct framed under `StructTag::ServiceAdvertisement` (`0x000F`). **Domain label:** the registry label is `vox/service-advertisement/v1` (already in `wire.rs`); the ADR body's earlier `vox/service-ad/v1` was shorthand — the registry label is authoritative and is what the code signs. The host seals an ad to each Dial-grant holder over that member's authenticated pairwise channel (ADR-004) via `seal_to_recipient`; a recipient `open_from_recipient`s it (decrypt → parse → verify author binding). No cleartext on the log; no responder-side filter.
- **Per-stream data path** (`tunnel::session`): one QUIC stream per tunneled TCP connection. The dialer sends a length-delimited `TunnelRequest{service_tag}`; `accept()` **itself enforces** `dial:<service_tag>` for the transport-authenticated peer (`VoxConnection::peer_id` + the ADR-007 `Evaluator`) *before any local connect* — the authorization gate lives in the module, not in a caller closure, so a misconfigured resolver cannot grant reach. The resolver is reduced to pure host-side Bind config (service tag → local endpoint, no auth). Unauthorized, unknown, and connect-failed all return a uniform `Denied` (dark services). Splice uses `tokio::io::copy_bidirectional` over a `tokio::io::join` of the QUIC `(recv, send)` pair (correct half-close). Verified by a real end-to-end test: a TCP app → local forward → QUIC tunnel → host → real TCP echo server → back, with authorization decided by a real evaluator; plus a denial test where an uncapability'd peer is refused.
- **ssh over Vox** (`tunnel::sshca`): issues a standard `ssh-ed25519-cert-v01@openssh.com` user certificate with the ADR-013 field mapping (`key_id`=Vox fingerprint hex; `valid_principals`=role/service tags verbatim incl. the `#`; the governing `dial:<service>` as a `vox-capability@vox.lux` extension; short validity window). The certified key is the **Ed25519 half** of the composite identity (OpenSSH speaks Ed25519; the full-composite binding is carried by `key_id` + transport auth). Signed by the channel SSH-CA Ed25519 key; `@cert-authority` line provided for host trust (no host-key TOFU). Issue→parse→verify round-trips; tamper and wrong-CA are rejected.
- **SOCKS5 front-end** (`tunnel::socks`): RFC 1928 no-auth negotiation + CONNECT request/reply, generic over the stream (tested over in-memory duplex); the caller maps the requested target onto a Vox service and splices to `session::dial`.
- **Identity-derived addressing** (`tunnel::addr`): `0xFD ‖ high-120-bits(SHA-256("vox/ula/v1" ‖ composite_pubkey))`, self-certifying and `verify_addr`-able; an address grants no reachability.

**Scope decision — the TUN/VPN datapath is deferred to the client (ADR-014), not built in `vox-core`.** *(2026-09-25: the
room-scoped family LAN is the exception. Its engine is in `vox-core` (`lan`) and needs no userspace TCP stack. Only the
device is per-platform, in the CLI. See "The family LAN" above.)* ADR-013 marks the TUN model *optional*; its datapath needs a privileged helper / `NetworkExtension` and a userspace TCP stack (`smoltcp`), which are platform-client concerns (the ADR ties TUN to ADR-014). `vox-core` therefore ships the **primary** per-stream SOCKS/port-forward model complete (the `ssh`-over-Vox path) plus the identity-derived addressing the TUN model will consume. This is a layering decision, not a false deferral: the per-service authorization, advertisement, addressing, and data-path are all complete and tested; only the OS interface binding (a client surface) is out of `vox-core` scope. `tun`/`utun` + `smoltcp` land with ADR-014.

- **A tunnel request names its channel (2026-09-20, M16.1).** `TunnelRequest` carried only a service tag,
  which cannot be authorized: a QUIC connection is per **peer**, not per channel (ADR-016), and the
  capability that permits a dial lives in a *channel's* ADR-007 evaluator — so a host told only
  `"ssh"` could not know which evaluator to ask, and two members who share several channels were
  ambiguous. The wire is now `[channel_id, service_tag]`: the dialer names the channel it claims the
  capability under, the host checks that claim against that channel's evaluator, and service resolution is
  asked per `(channel, tag)` so a service offered in one channel is not reachable by a capability granted
  in another. Refusals stay uniform (`TunnelStatus::Denied`) — unauthorized, unknown-channel,
  unknown-service and connect-failed remain indistinguishable on the wire. This is the same correction
  ADR-016 M14.7 made for the join, pairwise and sync streams, for the same reason.
- ~~**Capabilities are issued as log facts (2026-09-20, M16.1).**~~ **Removed 2026-09-24** (`grant_capabilities`, `can_dial`/`can_bind`, `exclude_from_service_grant`, `NodeCommand::GrantTunnel`, IPC `T_GRANT` — tag 10 retired, never reused). As first written: `ChannelState::grant_capabilities` issues
  an ADR-007 `AdminCert` delegating exactly the `bind:`/`dial:` capabilities asked for, appends it as a
  governance entry, and folds it into the evaluator — so a grant is a fact every member converges on
  through ordinary sync, not local configuration, and the evaluator's `is_within` check means no issuer can
  widen anyone's reach beyond its own. `can_dial` / `can_bind` on `ChannelState` are the queries. Proved
  both-sided: the issuer authorizes at once, the grantee's evaluator agrees the moment the entry arrives,
  a member with no grant and a different service are both refused, and the grant conveys **no** message
  consent (the two axes stay independent, as the Decision requires).
- **The surface a person uses (2026-09-20, M16.1b).** The library had no consumer but its own tests; now
  the node carries both halves.
  - **Host side.** `StreamKind::Tunnel` is dispatched (it was `NotYetSupported`) to `node::tunnel::serve`,
    which hands the stream to `session::accept` with a **snapshot** the actor takes of every open channel's
    evaluator and offered services. The snapshot matters twice: only the actor may read channel state, and
    a tunnel lives as long as the TCP connection it carries — possibly hours — so it must never reach back
    into the actor. A channel absent from the snapshot resolves to `None` and is refused exactly as an
    unauthorized request is, because telling the two apart would leak which channels this node is in.
  - **Bind configuration.** A channel persists `service_tag → local address` in its own sealed segment
    (`SEG_SERVICES`, `MAX_SERVICES = 64`), so a restart still offers what it offered. ~~`add_service` checks
    `bind:<tag>` against the channel's own evaluator: a node cannot offer what the log does not let it
    offer.~~ **The `bind:` check is withdrawn (2026-09-21, ADR-017 decision 3 as revised, M17.7):** offering
    a port of one's own machine is not the room's business, and the capability had exactly two sources —
    the genesis grant and `vox grant --may-bind` — both of which are withdrawn, so keeping the check would
    have left `vox serve` working only for a room's creator. Still in the tree
    (`governance/channel.rs:1232`); recorded as required work, not as done. This is configuration, never authorization — what a peer may *reach* is whether this host has
    approved that peer's key in this room (ADR-017 decision 3, revised 2026-09-21).
  - **Dial side.** `node::tunnel::Forward` binds a local TCP port and gives every accepted connection its
    own tunnel stream (ADR-013's one-stream-per-connection), so a forward carries as many connections as
    the application makes and a dead one takes nothing else with it. Binding happens eagerly, so a port
    already in use is an error the person sees rather than a task that dies quietly; dropping the forward
    stops the listener and leaves spliced connections to finish.
  - **A forward binds loopback only, and it is enforced (fixed 2026-09-21).** The listener hands whoever
    reaches it this node's own membership of the room, so a forward bound where the network can reach it
    exposes a room-bound service to everyone on that network — with no room, no passphrase, no key and no
    consent of their own. `vox up` had enforced this from the start (`node::up::serve` refuses a
    non-loopback bind and drops a non-loopback peer); `Forward::bind` did not, and it is the easier of the
    two to abuse, because `vox up` makes the caller supply a `.vox` name while a forward has its target
    already chosen. The check is in the node actor **before anything is dialled** (so a refused request
    costs no dial and leaks no traffic, and reports `Fault::NotLoopback` rather than a reachability
    failure) and again in `Forward::bind`, which creates the only socket and is therefore the structural
    backstop no caller can bypass. There is deliberately **no flag to override it**: a person wanting to
    re-export a room-bound service to a local network can run their own proxy in front of the loopback
    port and own that decision explicitly. Gate:
    `crates/vox-core/tests/sec_forward_binds_loopback_only.rs` — a non-loopback forward is refused, is
    refused *before* any dial (mutation-checked: removing the actor guard makes the node dial first and
    report `Unreachable`), leaves no listener on the port it asked for, and the same request on loopback
    passes the address check and fails only on reachability.
  - **The verbs.** `vox service add|remove|list`, `vox serve`, `vox forward` — each opens the room (a
    room's services and governance live inside the SEK-sealed store, so there is no offering or reaching
    without the passphrase), does its work and leaves; `forward` serves until interrupted and prints the
    `ssh -p <port>` line. Ids are given as unique prefixes of the base32 rendering, refused with a count
    rather than a guess when ambiguous. Passphrases are prompted for unechoed (crossterm raw mode) and
    read from a pipe when stdin is not a terminal, so nothing lands in shell history. **`vox grant` is
    removed** (2026-09-24): it had been reduced to a refusal stub, and before that it wrote capabilities
    nothing consulted. Approving a reader (`vox trust add`) is the grant (ADR-017 decision 3, revised).
    `vox service remove` asks the running node over its control socket when one holds the profile, so a
    service can be withdrawn from a live host (PRD-001 R22).
  - **Gate** (`node_m15_anchor_gate.rs`, release): Alice offers a localhost TCP service in a room, Bob
    joins through the anchor, and **before any grant his forward binds but carries nothing** — the service
    is dark to a member. Alice grants `dial:ssh`; the grant reaches Bob by ordinary sync, with nobody
    telling him, and his application connects to his own machine and gets byte-exact replies from Alice's
    service.
    **This gate still drives the withdrawn model** (`NodeCommand::GrantTunnel`, `node_m15_anchor_gate.rs:660`)
    and **must be rewritten** under M17.7 so its transition is Alice approving Bob's key rather than Alice
    granting `dial:ssh`. Recorded as required work, not as done: an earlier draft of this bullet stated the
    rewrite in the past tense before it had happened, which is the failure mode ADR-018 exists to prevent
    and is corrected here. The property under test does not change and the proof gets stronger — the
    transition becomes a single human act, and the negative half will hold against a member who has joined,
    holds the passphrase and paid the proof of work. Both clients are behind symmetric NATs, so the path is a relayed circuit and the anchor
    carried packets it cannot read. A second connection over the same forward works too. `ssh` over Vox is
    this test with `sshd` in place of the echo, which is why the echo is enough.
- **Tunnel honesty (2026-09-24, PRD-001 R22–R24; defects D6, D7, D11, D12).** Each fixed property below
  is proved by a shipped-binary gate that was mutation-checked red on the defect. The `tunnel_honesty_proof`
  harness waits 35 s after its guest joins before dialling the host, to step around D8 (the inline accept
  loop's 30 s deafness after a one-shot `vox connect`); that wait is to be removed once the loop is split.
  - **The SOCKS reply is the host's answer (R23, D6).** `session::dial` is split into `request` (send the
    request, await `TunnelStatus`) and `splice`; `vox up` replies only after `request` returns, `NotAllowed`
    for a host refusal and `GeneralFailure` for an unreachable host, and prints the reason on the
    operator's own terminal (`NodeEvent::ProxyRefused`). The early "succeeded" it replaced rested on a
    deadlock that does not exist: `accept` writes its status straight after its local connect.
    Gates: `tunnel_honesty_proof::a_refused_socks_connect_is_refused_in_the_reply_and_says_why` (code 2 in
    1.6–18 ms; mutation — reply "succeeded" before asking — returns code 0 and goes red), and
    `service_rehearsal_proof`, whose untrusted-joiner control used to accept the early success and now
    requires code 2 and the `the host refused` line. That control sits behind the rehearsal's second
    `vox connect`, which the inline accept loop locks out (`:490`, PRD-001 D8, owned elsewhere), so on this
    tree it is not reached; it was green 5/5 with the loop split.
  - **A refused forward resets the application (R23).** Gate: `tunnel_honesty_proof::
    a_refused_forward_resets_the_application_and_says_why` — the application reads a reset, not an EOF,
    and `vox forward` prints the reason.
  - **An abortive close is carried as one (R22/R23, D11).** The splice is no longer
    `copy_bidirectional`: a TCP read or write error on either end resets the QUIC stream with
    `TUNNEL_ABORT_CODE` (`0x1712`) and stops its receive half, and a reset arriving from the far end closes
    the local socket with zero linger, so the kernel sends RST. Previously the error path dropped the
    `SendStream`, which quinn finishes, so a backend reset reached the client as a clean EOF after a
    truncated reply. Gate: `tunnel_honesty_proof::a_backend_reset_reaches_the_far_client_as_a_reset`.
  - **Removing a service cuts its live sessions (R22).** The actor keeps a live `Offered` watch per
    channel beside `Reachers`; each serving task ends its session, reset with `REACH_WITHDRAWN_CODE`, the
    moment its tag leaves it. Gate: `tunnel_honesty_proof::
    removing_a_service_cuts_its_live_sessions_within_a_second`.
  - **A forward survives its host restarting (R24, D7).** `Forward::bind` takes a `HostDialer` instead of
    one `VoxConnection` and reaches the host per accepted connection through `up::open_tunnel`, which
    retries a path failure on a fresh connection within `HOST_PATIENCE` and never retries a refusal. A
    failed `accept` backs off (`ACCEPT_BACKOFF`) instead of ending the forward or spinning. Gate:
    `tunnel_honesty_proof::a_forward_carries_a_new_connection_after_its_host_restarts` — the host's
    `vox serve` is killed and the room brought back by `vox daemon` on a new port; the same forward carries
    a new connection. Mutation (the forward pins its first connection): red, `Connection reset by peer`
    at 59 s.
    - **The gate found a second defect, below the forward.** Instrumented, the forward re-reached the
      host every 10 s and every rung failed for five minutes: the board still named the old port, and the
      anchor said `relay cannot reach the peer`. `ConnectionManager::file` kept the *held* connection on
      a tie, so the anchor, holding a dead connection to the old host process that it would only learn
      was dead at the 60 s idle timeout, **retired the restarted host's live connection and closed it
      after the grace**. A direct newcomer from a *different direct address* now replaces the held one:
      the peer moved. A simultaneous dial from both sides arrives from the same address, so that
      tie-break is unchanged. Before this rule the gate passed 5 of 9 runs; after it, 5 of 5, each at
      ~60 s (both measured with the accept loop split), and 3 of 3 at ~60 s on the inline loop.
    - **Residual, stated:** those 60 s are the dialer's own stale connection. A request opened on it
      waits for QUIC's idle timeout before `open_tunnel` retries on a fresh one, so the first connection
      after a host restart takes about a minute. Bounding that wait is not done.
- **The SSH CA is narrowed to optional (decider, 2026-09-21).** The Decision above offers "`ssh` over Vox"
  partly as a Vox-issued OpenSSH certificate bound to the Vox identity, replacing host-key TOFU and
  `authorized_keys`. That is **no longer a requirement of this ADR.** The decider's reasoning, recorded
  because it generalises: Vox is the layer traffic is routed and authorized *over*, and a room-bound
  service should not bring its own authentication scheme — "way too much overhead and possibly weaker
  security outcomes." A second trust root, certificate lifetimes, and a per-protocol credential path are
  large surface for gain that only materialises at fleet scale; a carried protocol authenticating itself
  exactly as it always has is both simpler and better understood. The mental model is Tor's hidden
  service: the overlay decides **reach**, the service decides **who its users are**.
  What this ADR therefore specifies is the **per-stream port-forward model**, complete: a local port
  forwarded to a member's service, gated by the `dial:` capability. "`ssh` over Vox" means forwarding to
  a real `sshd`, which is what ADR-016's M16.1 gate proves. The CA remains a coherent *optional* later
  capability — the case for it is "the room's membership decides who may `ssh` in, without touching
  `authorized_keys`", which is real for a fleet and pointless for one box — and if it is ever built it
  gets its own ADR with its own threat model, rather than riding along in this one. The existing
  `tunnel::sshca` module stays as the researched seam it is, unwired, and is no longer counted as an
  unfinished obligation of this ADR.
- **Known gaps (recorded 2026-09-19, revised 2026-09-20).** ~~No CLI~~ — `vox service` / `vox grant` /
  `vox forward` exist (M16.1b); `vox up` does not, and may not need to. ~~Consumers are the in-crate tests
  only~~ — the node is the consumer. What remains: tunnel session establishment is still not recorded as
  **signed events** (the "accountability" line has no entry type). The ~~**SSH CA**~~ — no longer an obligation of
  this ADR (narrowed to optional above); `tunnel::sshca` remains an unwired seam whose gaps
  (no capability-tree binding, `verify_user_cert` ignoring extensions/critical options, the capability in
  an extension rather than a critical option) would be that future ADR's to close, not this one's. **SOCKS** is still a codec with no listener
  composing negotiate → CONNECT → service map → `session::dial` → reply, and `Reply::NotAllowed` is never
  emitted. *(Stale: `vox up` is that listener (ADR-017 decision 5), and since 2026-09-24 it replies
  `NotAllowed` when the host refuses — see "Tunnel honesty".)* Service **advertisements** exist only pairwise (the audience-encrypted `0x000F` entry does not),
  so a member learns another's service tags out of band — **ADR-017 M17.4** owns closing this, having
  chosen the audience-encrypted form over a room-wide announcement. The person-facing surface
  (`vox serve` / `vox connect`, capability-bearing rooms, anchors as configuration) is ADR-017's. The TUN/VPN datapath remains ADR-014's, as the
  Decision says.

- **`vox forward` asked once and gave up (2026-09-23).** A one-shot verb starts a node, opens the
  room and dials, all inside a few seconds — and at the moment of that dial the node has usually not
  finished connecting to the room's anchor. `helpers()` is therefore empty, no circuit rung can be
  built, and the only rung attempted is a direct dial, which cannot succeed between two peers behind
  NATs. The command returned `Fault::Unreachable` immediately and the person was told to check a
  permission. Measured against a real always-on anchor: four build configurations, four failures,
  `direct=0 helpers=0 peers=0` at the moment of the dial.
  `vox up` had already solved exactly this and `forward` never got the same treatment — `up` binds
  before it can reach the host *deliberately* and waits inside the request
  (`node::up::reach_host_with_patience`, `HOST_PATIENCE`). `forward` now waits with the same
  patience, applied from the CLI rather than on the actor, so the node keeps running between
  attempts and the actor is never blocked for longer than one attempt. Each attempt's rung verdicts
  are printed while it waits.
  **And this path has no proof at all — including the gate that looks like one.**
  `node_m17_serve_gate` does call `NodeCommand::Forward`, so it reads as covering this. It does not:
  its joiner joined in-process seconds earlier, so `reach` returns at once from
  `ConnectionManager::existing` and **the ladder inside `Forward` is never run**. The gate is green
  while the path a real user takes is structurally unable to work — a green test that does not
  discriminate, which ADR-018 §4 warns is worse than no test. CI says the same thing outright:
  `cross-process-tunnel` sits on `VOX_PROOF_ALLOW_UNPROVEN` and no tunnel proof file exists.
  What closes this is a person running `vox forward` against a real anchor on a real network. Nothing
  short of that is evidence, and the gate must not be cited as if it were.

## Links
**Depends on**: ADR-002, ADR-007, ADR-011, ADR-012.
- Depended on by: ADR-014 (client surfacing).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
