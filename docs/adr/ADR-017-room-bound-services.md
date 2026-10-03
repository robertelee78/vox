# ADR-017: Room-Bound Services

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (third revision 2026-09-21: consent-bound services; fourth revision 2026-09-24:
local names; addressing restated by the decider 2026-10-02).

Built on integrate/v0.3.0:
- the reach gate, "in the host's trust keyring AND a current author of the room"
  (`NodeActor::refresh_reachers`, `tunnel::session::accept`), with the genesis service grant
  consulted by nothing (`Evaluator::service_grant_verdict` returns `None`), no `vox grant` verb and no
  `bind:` check on offering a service (3.1–3.11, M17.7);
- no consent on join, and witnessed board admission (3.4, M17.6);
- `vox trust remove` changing the lock in every shared room (10.8, M17.14);
- the live reacher set, teardown of live and parked sessions, and the reason given to the far end
  (decision 10, M17.11);
- the per-member tunnel cap (3.13);
- `vox up` as an unprivileged SOCKS5 proxy, with the room optional (decision 5, M17.3);
- the carried session seeing only loopback, and attribution at the gate (decision 6);
- anchors as configuration, followed while a daemon runs (decision 7, M17.4);
- refusal of rooms made before v0.3.0 (11.4).

Where this tree's code differs from these requirements:
- **`vox serve`** still creates a room, with a generated passphrase, and shares the named services in
  it. Binding a service into a room that already exists is `vox service add`. Naming the
  audience and non-audience is not built (4.1, 4.2).
- **Passphrase rotation** is removed by V030-32, but its code is still on this tree; the removal is
  pending under #380 (11.3).
- **Proofs**: the parked-stream withdrawal has no real-binary proof yet, RP-10 (#117).

**Date**: 2026-09-21
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: services, tunneling, ux, consent, discovery, hidden-service

## Context

ADR-013 makes the overlay carry TCP and UDP between members. This ADR specifies the product built on
it: a person shares a local service with a room, and the people they trust in that room reach it with
ordinary tools. The aim is to replace a Tor private service.

The decider's rule: *"When I am approving someone to read my messages in a room I am also approving
them to use any service that I have granted to that room."* And its converse: someone who joins and
whom the host has not approved *"should not know about that service"*.

Joining a room is a passphrase and a proof of work, which is not a decision about a person. The
approval to read is such a decision, already made per person. So reach rides on the approval to read.
It needs no credential, no grant and no second decision.

"Tunnel" names the ADR-013 mechanism: one QUIC stream carrying one connection. A room-bound service
is what a person offers. A tunnel is how bytes reach it.

## Requirements

### 1. The name is a host-committed random label

- **1.1** Superseded by decision 12. A host-committed name (`H("vox service name v1" ‖ host_pk ‖
  nonce)`) MUST NOT be built. M17.9 is withdrawn.

### 2. Nothing is ever exposed implicitly

- **2.1** A local port MUST become reachable only when a person declares it as a service in a room.
  Any other action MUST NOT expose a local port.
- **2.2** Declaring a service MUST NOT authorize anyone. Reach is decision 3's alone.

### 3. The trust keyring is the authorization

- **3.1 The gate.** A service a host bound to a room MUST be reachable by exactly those nodes that
  are in that host's trust keyring **and** are current members of that room, and by nobody else:

  ```text
  reach(member, service)  ⟺  member ∈ host's trust keyring
                          ∧  member ∈ the bound room's current author set
  ```

  The host MUST compute this itself and check it at dial time. A client's belief about it grants
  nothing.
- **3.2 Approving is trusting.** Approving a node to read this node's messages is adding it to the
  trust keyring (`vox trust add`); there is one decision, not two. Approval MUST confer reach to every
  service the host binds to any room both are in, at once and with no second act. That includes a
  service bound before the approval, and a room the approved node joins later.
- **3.3 Membership grants no reach.** Joining a room, holding its passphrase, paying its proof of
  work, being admitted as an author on any board, or answering someone's join MUST NOT confer reach.
- **3.4 Every consent is a human act (M17.6).** Consent is per pair and per direction. Each grant
  MUST be caused by a keyring entry, made by a person. In particular:
  - `join` MUST NOT release this node's sender key to the responder. The responder's sending chain
    comes from `PairwiseFrame::Open`, an empty sealed message that carries no key and no grant.
  - A member bundle record MUST carry an `Admission` (`Creator`, or `Witnessed(JoinWitness)`, struct
    tag `0x0014`) inside its signed body. A board key MUST become an author only through
    `ChannelState::admit_from_board`, and a witness MUST count only if this node already admits its
    signer. Admission MUST run to a fixpoint, bounded by `MAX_ADMISSIONS_PER_SWEEP` (8).
  - **Known limit:** a witness makes injection attributable, not impossible. A member can sign a
    witness for a key that never joined.
- **3.5 Not transitive.** A host MUST NOT inherit identities from another node's keyring.
- **3.6 Per-room scoping.** A service bound to two rooms MUST be reachable by the approved members of
  each room, judged per room at the dial gate. A host-wide union of readers MUST NOT be used.
- **3.7 Unapproved members learn nothing.** A member the host has not approved MUST NOT be able to
  reach, enumerate or learn of the host's services. A host MUST NOT announce a service to a room in
  plaintext. Knowing of a service MUST NOT confer reach.
- **3.8 The approval says what it grants.** The approval surface MUST state that approval confers
  reach to the host's services (built: `vox trust add` says so).
- **3.9 No narrower reach.** Reach MUST NOT be narrowed below "this host's approved members in this
  room". There is no time-bounded reach and no reach without read. A host that wants a subset uses a
  second room.
- **3.10 Only the host cuts reach.** Only the host MAY withdraw a member's reach to its services. A
  room's creator or admin MUST have no lever over another member's services.
- **3.11 Withdrawn, and MUST NOT exist:** the genesis service grant as authorization
  (`GenesisBody::service_grant`); `service-grant-exclusion` (`0x0013`), whose tag MUST NOT be reused;
  `vox grant`; the `bind:` capability class and `add_service`'s `can_bind` check;
  `Evaluator::build_with_members(authors.keys())`; and automatic consent on join.
- **3.12 One rule for every room.** There are no node kinds and no room types. The same rule applies
  in every room.
- **3.13 Per-member tunnel cap (#272).** A host MUST refuse a new tunnel from a member past
  `TUNNELS_PER_PEER` (16) live tunnels to that member, at once and with a reason that says how to free
  one (ADR-013 T-15). It MUST NOT queue the tunnel, or let it share the connection's window.

### 4. Serving

- **4.1** `vox serve` MUST bind a service into a room that already exists. It MUST NOT create a room,
  a passphrase or an invite. Status: not built. `vox serve <ports>` creates a room; `vox service add`
  binds into an existing one.
- **4.2** `vox serve` MUST name, by name and not by count, the members who can reach the service and
  the members of the room who cannot. Status: not built. `vox serve` prints the rule, not the lists.
- **4.3** A shared service MUST have a name, given by the sharing node and unique per node per room.
  `vox serve` with no name MUST be refused (decision 12, #339).
- **4.4** The service's name (12.6) MUST be what the host translates to the local endpoint it
  declared. The endpoint defaults to `127.0.0.1:<port>`. `--at` MUST set a different one.
- **4.5** `vox serve` MUST NOT refuse for lack of an anchor. A host found directly by its guests
  needs none. It MUST withhold an address that would name no route at all, and say why
  (`NodeEvent::AddressWithheld`, V210-96).
- **4.6** A passphrase that `vox serve` generates (`node::passphrase`) MUST be used exactly as
  printed, byte for byte, on both sides. Its hyphens are part of the secret, and they MUST NOT be
  stripped.

### 5. One local entry point: a SOCKS5 proxy (`vox up`)

- **5.1** `vox up` MUST run a SOCKS5 proxy on loopback, by default `127.0.0.1:1080`. The proxy MUST
  resolve `.vox` names itself (`socks5h`), and MUST carry each connection to the host as a tunnel.
- **5.2** With no room argument, `vox up` MUST run in the node already holding the profile
  (`vox daemon`). It MUST resolve names against every room that node holds, as they stand when each
  connection asks. A single room MAY be named.
- **5.3** The proxy MUST refuse a literal-address CONNECT and a name it cannot resolve. It MUST NOT
  act as a general-purpose proxy.
- **5.4** This path MUST NOT need privilege: no device, no route, no firewall rule, no port
  below 1024, and no resolver entry.
- **5.5** `vox up` MUST print the `ssh` `ProxyCommand` line for `*.vox`. Tools with no proxy support
  use `vox forward`.
- **5.7** `vox forward` MUST take only a service's address, `vox forward <service>.<node>.<room>.vox
  [<local>]`, resolved as 12.1–12.6 by the node holding the profile (the running daemon, else a node
  the verb unlocks, which reopens the rooms the profile holds open). Any other first argument MUST be
  refused. There is no form naming a room and a member (decider, 2026-10-03: "address only").
- **5.6** The proxy MUST bind before it can reach any host. Each request MUST wait for its host for
  up to `HOST_PATIENCE` (300 s), within that request's own task (`up::reach_host_with_patience`).
- **5.7** A network interface MUST NOT be the primary path. Automap, a transparent proxy or an
  interface MAY be added later, as an addition.
- **5.8** Accepted: a tool configured for plain `socks5` asks the system resolver about a `.vox` name
  first, which leaks the name (PRD-001 R21).

### 6. The carried session has no IP addresses of its own

- **6.1** The host MUST connect to the local endpoint it declared, so the carried service sees every
  Vox client as loopback.
- **6.2** The host MUST check the client's transport-authenticated fingerprint, and the room it
  names, against decision 3 before any local connect.
- **6.3** Vox MUST NOT prepend anything to the carried byte stream, and MUST NOT mint a credential for
  the carried protocol.
- **6.4** The host node MUST report who reached which service (`NodeEvent::TunnelServed`, printed by
  `vox serve`).
- **6.5** Vox MUST NOT offer IP-level anonymity or a relay-mandatory mode. The two nodes' addresses
  are visible to each other and to an on-path observer whenever a direct path is used. Audience size,
  volume and timing are not padded.

### 7. The anchor is configuration, not an argument (M17.4)

- **7.1** `vox node` MUST write its own anchor spec to `<config_dir>/anchors`, and every command MUST
  read that file. The file is machine-wide, shared by every profile on the machine.
- **7.2** `--anchor` MUST merge with the file, not replace it.
- **7.3** The file MUST hold one anchor spec per line (`<fingerprint>@<multiaddr>`, or a host name and
  port). `#` comments and blank lines MUST be skipped. The file MUST be rewritten whole on every
  address change, through a temporary file and a rename. A malformed line MUST NOT be skipped
  silently. The file holds no secret.
- **7.4** A running daemon MUST re-read the file and re-resolve every spec every `ANCHOR_REFRESH`
  (30 s). An anchor that moved MUST replace its old address, in the node's set and in each room's
  stored set. **Known limit:** a host name whose record moves while the file is untouched takes the
  same code path, but is not measured.
- **7.5** An anchor MUST be needed only to bridge hosts that cannot otherwise reach each other
  (ADR-012).

### 8. How many steps this is

- **8.1** A host MUST need one command to offer a service in a room it shares with its guests, and
  no act per guest. A guest MUST need `vox up` and one `ProxyCommand` per machine, and nothing per
  use beyond the tool itself.
- **8.2** A host that is publicly reachable, granted a port mapping, or reachable directly by its
  guest (the same LAN, for instance) MUST need no anchor. An anchor line is needed once, only when both
  ends are behind NAT and neither can reach the other.
- **8.3** A guest that has just joined a room approves who may read it. That act is not part of the
  service flow and grants the guest nothing.

### 9. The descriptor is content, sealed to the host's ring

- **9.1** Superseded by decision 12. A service descriptor MUST NOT be built. M17.10 and M17.12 are
  withdrawn. The rule it served stands as 3.7.

### 10. Withdrawing trust is immediate, and says so (M17.11)

- **10.1** Removing a node from the host's keyring MUST withdraw its reach at once. The host MUST
  reset that node's live sessions with `REACH_WITHDRAWN_CODE` (`0x1711`), not finish them.
- **10.2** The far end MUST be told why: the dialer maps the reset to `Error::TunnelRevoked`, the node
  emits `NodeEvent::ReachWithdrawn`, and `vox up` prints that the host withdrew access and that there
  is nothing to retry.
- **10.3** Every later dial MUST be refused at the gate, whatever the client remembers.
- **10.4** A request on a stream that opened before the withdrawal MUST be judged after it is parsed,
  against the current reacher set. The service MUST NOT be dialled for it.
- **10.5** The reacher set MUST be a live handle (`node::tunnel::Reachers`, a `tokio::sync::watch`).
  It MUST be recomputed when the keyring or a room's author set changes, and on each accept. Serving
  tasks MUST be woken only when the set really changes (`publish_reachers`). A locked node MUST NOT
  recompute it, because the keyring is cleared while locked and an empty set would read as everyone
  withdrawn.
- **10.6** A refused dial MUST tell the peer nothing beyond its SOCKS reply. The dialing node prints
  the reason locally (ADR-013 T-19).
- **10.7** Restoring trust MUST restore reach in the same act. There is no separate service state.
- **10.8 (M17.14)** Removing a node from the keyring MUST also change the lock: rotate this node's
  sender key in every room shared with that node and re-key everyone still trusted, best-effort, with
  the tick retrying whoever is offline.
- **Known gap:** it is not confirmed whether the spurious-wake fix accounts for the mid-stream reset
  once seen in `service_rehearsal_proof`. If a reacher set moves for a moment (an author set rebuilt
  during sync, say), the teardown still fires. If it recurs, the fix is for the actor to announce a
  withdrawal explicitly, rather than have a serving task infer it from set membership.

### 11. Lifecycle

- **11.1** When a host is no longer a member of a room, its services in that room MUST stop being
  reachable, and their live sessions MUST be torn down. A room the node no longer holds MUST have an
  empty reacher set.
- **11.2** Leaving one room MUST NOT disturb a service bound to another.
- **11.3** Passphrase rotation is removed (V030-32). Status: its code is still on this tree, and its
  removal is pending under #380.
- **11.4** A room made before v0.3.0 MUST be refused, with "make the room again"
  (`Fault::RoomFromBeforeV030`). The genesis service grant MUST be removed, along with `<room-id>.vox`
  resolving to a room's creator (R44, #94; #339). The grant slot stays in the genesis layout, always
  empty; a genesis carrying a token is refused as a room made before v0.3.0. `0x0013` is reserved.
- **M17.8** A governance entry MUST count only if its epoch equals the epoch established in its
  strict causal past (`Evaluator::in_effect`, ADR-007), so a replayed pre-rotation grant buys nothing.
- **M17.13** Superseded by 11.4.

### 12. Addresses

- **12.1** Only `service.node.room.vox` MUST connect. `node.room.vox` and `room.vox` MUST resolve to
  nothing: no connection, no refusal naming services, and no listing.
- **12.2** The node and room parts MUST be the resolving client's own aliases, or the fingerprints.
  The service part MUST be the name the sharing node set, which is unique per node per room, or the
  service's fingerprint, `SHA-256("vox/service-fingerprint/v1" ‖ room id ‖ sharer fingerprint ‖ name)`.
- **12.3** Wherever Vox shows a service address, it MUST render the node and room parts with the
  viewer's own alias, or the fingerprint where the viewer set none.
- **12.4** `<room-id>.vox`, resolving to a room's creator, MUST NOT resolve. The genesis service grant
  behind it is removed.
- **12.5** A three-part name whose words match nothing on this node, or more than one thing, MUST be
  refused with a sentence saying which, to this node's operator only. Only the SOCKS reply code
  reaches the tool.
- **12.6** The port in a SOCKS request MUST NOT select the service; the name does. A UDP service is
  asked for as `udp/<name>`.
- **12.7** A service name MUST be one DNS label of at most 63 characters. `vox serve` takes each share
  as `<name>=<port>[/tcp|/udp]`. One name MUST NOT be shared twice by a node in a room, over either
  transport; the second share MUST be refused, naming it. A service moves by being removed and shared
  again.
- **12.8** A share MUST be stated on the room's log as a `0x0018` service-share statement
  (`vox/service-share/v1`), signed by its sharer: the name, its transport, and whether it is shared or
  withdrawn. The last statement a sharer made about a name wins. A member that has left shares nothing.
  A transient offer (a file being handed over) MUST NOT be stated.
- **12.9** A member MUST be able to list what is shared in a room, with each address rendered as in
  12.3 and who shared it: `vox service list <room>`, and the TUI's Shared pane.
- **12.10** `vox serve` MUST print each share's address with the service name and the fingerprints in
  the node and room places.

Built (#339): `node::resolver`, `governance::share`, `ChannelState::{say_share, shares}`,
`vox serve <name>=<port>`, `vox service list`, `vox forward <service>.<node>.<room>.vox [<local>]`.
Proved by `crates/vox-tui/tests/a_service_is_reached_only_by_its_address_proof.rs`.

### 13. Boundaries

- **13.1** Vox MUST NOT add an authentication scheme for the carried service. The service
  authenticates its own users as it always does.
- **13.2** A service MUST NOT be reachable by a non-member. There is no anonymous or public tier.
- **13.3** An address MUST NOT be a capability. Holding a name MUST NOT be sufficient to connect.
- **13.4** There MUST be no global namespace and no name resolution off the machine.

## Fixed since

- **Join auto-consent** (`join` released the sender key to the responder): removed by M17.6. Proof:
  `no_consent_without_a_ring_entry_proof.rs` (RP-28, #135).
- **`bind:` left `vox serve` working only for a room's creator**: removed with M17.7.
- **Stale output** (`vox serve` "anyone who joins with both may reach it"; `vox service add` "dark
  until you `vox grant`"): replaced in M17.7.
- **The first CONNECT refused before the board was read**: fixed by `up::reach_host_with_patience`
  (5.6).
- **Recomputes tore down live sessions** (unconditional `send_replace` on every accept): fixed by
  `publish_reachers` (10.5).
- **An anchor host name resolved once, at startup**: fixed by `ANCHOR_REFRESH` re-resolution (7.4).
  Proof: `a_daemon_follows_its_anchor_proof.rs` (RP-32, #139).
- **Open proof gap (M17.17): the accept loop serialised handshakes**, locking out a second joiner
  for up to 30 s. Closed in v0.2.8: each handshake runs on its own task, bounded at
  `HANDSHAKES_IN_FLIGHT` (64), with `retry()` or `refuse()` at the cap and never a queue, and the
  duplicate-connection tie-break uses an order-independent TLS-exporter key (`tie_key`). Proof:
  `a_second_joiner_is_not_locked_out.rs`.

## Consequences

- Reading and reaching are one decision, and every such decision is an explicit human act. Nothing
  new is minted, stored or sealed for authorization.
- Host and guest need to share a room first. A joiner is readable by nobody until it approves
  someone.
- Reach cannot be narrowed below "this room's members in my ring". Only the host can cut it.
- IP-based controls on the carried service (`sshd` host patterns, `hosts.allow`, `fail2ban`) do
  nothing for Vox clients. Attribution is the node's job (6.4).
- A tool has to be told about the proxy once, as with Tor.

## Related ADRs

ADR-005 (invite and passphrase), ADR-006 (sender keys), ADR-007 (per-sender consent and revocation),
ADR-012 (reachability and anchors), ADR-013 (the tunnel data path), ADR-014 and ADR-015 (the clients
that surface these verbs), ADR-016 (the node), ADR-018 (proof by the shipped binary), ADR-020 (the
trust keyring), ADR-022 (UDP services).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
