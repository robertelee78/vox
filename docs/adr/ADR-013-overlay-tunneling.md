# ADR-013: Overlay Tunneling (TCP-over-Vox)

**Status**: proposed
**Date**: 2026-06-19
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

- **Per-stream SOCKS / port-forward (ssh-style) — primary.** Targeted, least-privilege: forward a
  single local port to a specific member's service, or expose a local SOCKS proxy. This is the
  default and the path for `ssh` over Vox.
- **TUN virtual interface (VPN-style) — optional.** A `utun` interface with identity-derived
  addressing for "everything just routes" between members; on macOS via `NetworkExtension` /
  privileged helper (notarized, ADR-014). Per-service authorization (below) still applies on the
  TUN path — the interface is convenience, not a bypass of policy.

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
- **Chat membership grants NO tunnel reach — this is a hard invariant (but the two coexist freely in one
  swarm).** Joining a channel, holding the passphrase, or being consented-to for *messages* conveys
  **zero** tunnel reachability *by itself*. Tunnel capabilities are **never inherited from membership** —
  they are **explicitly granted per member** (`bind:`/`dial:`). A **single swarm can absolutely carry
  both comms and tunnels at once** (the compute-node case: the admin grants `dial:`/`bind:` to the
  members that need them, in the same channel that also carries chat); what is forbidden is *automatic*
  tunnel access falling out of chat membership. So the "here, join my chat" → "now I'm on your LAN" path
  is structurally impossible: a chat invitee with no explicit `dial:` grant cannot enumerate or reach any
  service (dark services, default-deny, above), even with full message consent and a valid ULA address —
  while a teammate you *do* grant `dial:#ssh-hosts` reaches exactly that service and nothing more.
- **Tunnel authorization is capability-gated and epoch-bound — orthogonal to message consent.** A tunnel
  is reachable only by a member holding a valid, unrevoked `dial:<service>` capability (ADR-007 lattice)
  for the current epoch. Revoking a tunnel = revoking that **capability** (admin-delegation-revocation,
  ADR-007) or rotating the passphrase (epoch). **Revoking per-sender *message* consent / Block (ADR-007)
  does NOT touch tunnel access, and vice-versa** — the two axes are independent (chat readability vs
  service capability); a member can be blocked in chat yet retain a granted tunnel, or have a tunnel
  revoked while remaining a full chat participant.
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

- **Authorization reuses the single ADR-007 evaluator** (`tunnel::authz`): `can_dial`/`can_bind`/`authorize_dial`/`authorize_bind`/`dial_audience` are thin wrappers over `Evaluator::grants(key, Capability::Dial/Bind(tag))`. No second engine — the one golden-vector suite covers tunnel authz. The `Bind`/`Dial`/`Role` capability vocabulary was pre-provisioned in the M6 lattice (`governance::capability`), so M11 only consumes it. Default-deny, Bind≠Dial, and "chat membership grants no tunnel reach" all fall out of consulting only the capability lattice.
- **Discovery-gating by encryption** (`tunnel::service`): `ServiceAdvertisement { member_id, service_tag, endpoint }` is a composite-signed struct framed under `StructTag::ServiceAdvertisement` (`0x000F`). **Domain label:** the registry label is `vox/service-advertisement/v1` (already in `wire.rs`); the ADR body's earlier `vox/service-ad/v1` was shorthand — the registry label is authoritative and is what the code signs. The host seals an ad to each Dial-grant holder over that member's authenticated pairwise channel (ADR-004) via `seal_to_recipient`; a recipient `open_from_recipient`s it (decrypt → parse → verify author binding). No cleartext on the log; no responder-side filter.
- **Per-stream data path** (`tunnel::session`): one QUIC stream per tunneled TCP connection. The dialer sends a length-delimited `TunnelRequest{service_tag}`; `accept()` **itself enforces** `dial:<service_tag>` for the transport-authenticated peer (`VoxConnection::peer_id` + the ADR-007 `Evaluator`) *before any local connect* — the authorization gate lives in the module, not in a caller closure, so a misconfigured resolver cannot grant reach. The resolver is reduced to pure host-side Bind config (service tag → local endpoint, no auth). Unauthorized, unknown, and connect-failed all return a uniform `Denied` (dark services). Splice uses `tokio::io::copy_bidirectional` over a `tokio::io::join` of the QUIC `(recv, send)` pair (correct half-close). Verified by a real end-to-end test: a TCP app → local forward → QUIC tunnel → host → real TCP echo server → back, with authorization decided by a real evaluator; plus a denial test where an uncapability'd peer is refused.
- **ssh over Vox** (`tunnel::sshca`): issues a standard `ssh-ed25519-cert-v01@openssh.com` user certificate with the ADR-013 field mapping (`key_id`=Vox fingerprint hex; `valid_principals`=role/service tags verbatim incl. the `#`; the governing `dial:<service>` as a `vox-capability@vox.lux` extension; short validity window). The certified key is the **Ed25519 half** of the composite identity (OpenSSH speaks Ed25519; the full-composite binding is carried by `key_id` + transport auth). Signed by the channel SSH-CA Ed25519 key; `@cert-authority` line provided for host trust (no host-key TOFU). Issue→parse→verify round-trips; tamper and wrong-CA are rejected.
- **SOCKS5 front-end** (`tunnel::socks`): RFC 1928 no-auth negotiation + CONNECT request/reply, generic over the stream (tested over in-memory duplex); the caller maps the requested target onto a Vox service and splices to `session::dial`.
- **Identity-derived addressing** (`tunnel::addr`): `0xFD ‖ high-120-bits(SHA-256("vox/ula/v1" ‖ composite_pubkey))`, self-certifying and `verify_addr`-able; an address grants no reachability.

**Scope decision — the TUN/VPN datapath is deferred to the client (ADR-014), not built in `vox-core`.** ADR-013 marks the TUN model *optional*; its datapath needs a privileged helper / `NetworkExtension` and a userspace TCP stack (`smoltcp`), which are platform-client concerns (the ADR ties TUN to ADR-014). `vox-core` therefore ships the **primary** per-stream SOCKS/port-forward model complete (the `ssh`-over-Vox path) plus the identity-derived addressing the TUN model will consume. This is a layering decision, not a false deferral: the per-service authorization, advertisement, addressing, and data-path are all complete and tested; only the OS interface binding (a client surface) is out of `vox-core` scope. `tun`/`utun` + `smoltcp` land with ADR-014.

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
