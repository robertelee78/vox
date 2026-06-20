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
- **Consent + revocation gate tunnels.** Tunnel rights are bound to channel membership and
  per-sender consent (ADR-007): revoking a member (or a passphrase-epoch rotation) revokes their
  tunnel access going forward, exactly like message access.
- **SSH-CA mapping (concrete).** "ssh over Vox" uses the member's verified Vox identity (ADR-002) as
  the authority. Vox issues a standard **OpenSSH certificate** with this field mapping: `key_id` = the
  Vox identity fingerprint; `valid_principals` = the granted role/service tags (e.g. `#ops`);
  `critical_options`/`extensions` carry the governing Vox capability (`dial:<service>`); `valid_after/
  before` = a short window (**default 5 min**). It is signed by the **channel SSH-CA key**, which is an
  `admin`-delegated capability cert in the ADR-007 tree. The SSH host trusts that CA pubkey via an
  `@cert-authority` line (delivered as a channel entry), so there is **no host-key TOFU** — the host's
  identity is the verified Vox identity.

### Addressing & name resolution

- **Identity-derived addressing (concrete derivation).** For the TUN model, each member's address is
  `addr = 0xFD ‖ high-120-bits( SHA-256("vox/ula/v1" ‖ composite_identity_pubkey) )` — a self-certifying
  /128 in the `fd00::/8` ULA range (CGA/Yggdrasil-style). It is unforgeable (bound to the key), needs no
  allocation, and a peer **verifies** an address by recomputing it from the claimed identity; 128-bit
  output makes collision negligible. For the SOCKS/forward model, services are addressed logically by
  `(member identity, service name)`.
- **Channel-scoped resolution (single mechanism, consistent with discovery-gating above).** A service
  advertisement is an **audience-encrypted log entry**: an inner signed record `(member, service,
  endpoint)` sealed to the current Dial-grant set (keyed per-recipient like an SKDM, ADR-006) and
  carried as an opaque payload on the replicate-all log (ADR-008). A requester resolves a name purely
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
