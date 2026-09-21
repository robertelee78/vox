# ADR-017 — Room-Bound Services (the Tor-hidden-service equivalent)

**Status**: **revised — the authorization model of decision 3 is withdrawn.** Decisions 5, 6 and 7 are
built and shipped in v0.1.0 (`node::up`, `node::resolver`, `<config_dir>/anchors`). Decisions 1, 3, 4, 8,
9 and 10 are **proposed and not built**; what ships today implements the withdrawn model and is a live
vulnerability until M17.6–M17.10 land.
**Date**: 2026-09-21
**Updated**: 2026-09-21 (third revision) — **capability-bearing rooms are withdrawn.** Decision 3 held
that *"'may this member dial it' and 'is this person a member' are the same question, asked once."* That
is refuted: admission to a room is passphrase + proof-of-work, so under it any party who obtains an
address and a passphrase — or, via the vouching path, any party a single member syncs — is authorized to
dial every service bound to that room. Authorization is now **per-sender consent**: a service is
reachable by exactly the members its host has approved to read its messages in the bound room, and by
nobody else. The genesis service grant, its `service-grant-exclusion` (`0x0013`) and the `vox grant`
verb are all withdrawn with it. The `.vox` name changes from the channelID to the **service's own
persisted keypair**, following Tor's construction (`/opt/tor` `hs_common.c:902`) rather than inventing a
room-derived one. Decision 5's SOCKS5 entry point, decision 6's addressless carried session and
decision 7's anchor configuration are unaffected and stand as built. Descriptor freshness is keyed to the
host's ADR-006 `chain_id` rather than the channel epoch — see decision 9, which records why the decision
as first taken was on a wrong premise.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: services, tunneling, ux, capability, consent, discovery, hidden-service

## Context

ADR-013 makes the overlay carry arbitrary TCP between members, and ADR-016 M16.1 proved it end to end:
a TCP service on one machine's loopback, reached from another machine's loopback, between two clients
behind symmetric NATs, through the user's own anchor. The mechanism works.

**The mechanism is not the product.** Reaching that service today takes six steps:

1. run an anchor node, note its fingerprint;
2. pass `--anchor <fp>@<multiaddr>` to every client, every command;
3. create a room;
4. share the invite link;
5. share the room passphrase, separately;
6. grant the guest the `dial:<tag>` capability once they have joined.

A Tor hidden service takes two on the host side: add two lines to `torrc`, read the `.onion` address
(decision 8 counts both sides carefully). The author's stated intent for Vox is to *replace* a Tor
private service, so six steps against two is a product failure, not a rough edge. This ADR specifies
the surface that closes the gap, and names the thing being offered so the rest of the documentation can
stop calling it "a tunnel".

### Three ways to remove step six, and why the third is the right one

Step six — the host waiting for a guest to appear and then granting them something — is the round trip
Tor does not have. There are exactly three ways to be rid of it, and the history of this ADR is the
history of choosing among them.

1. **Make the address the authorization.** Tor's answer: knowing a `.onion` is sufficient to connect.
   Rejected for Vox, because a leaked string would then be a leaked service with no second factor and
   nothing to revoke.
2. **Make membership the authorization.** This ADR's first answer (the withdrawn decision 3): the
   genesis confers `dial:` on every admitted member, so joining *is* being granted. Withdrawn, because
   admission is not a human decision — it is a passphrase and a proof of work, and a member who merely
   syncs another peer's board admits its authors without any human approving anything. The step was not
   removed, it was **delegated to an adversary**.
3. **Notice that the human decision already happened.** The host already approves, per member, who may
   read its messages (ADR-007 per-sender consent): joining a room grants nothing readable until each
   existing member independently approves the joiner's key. That approval is a deliberate, human,
   per-person act that the host performs anyway. **Binding services to it removes step six without
   adding any mechanism at all** — there is no new credential, no new log entry kind for authorization,
   and no new decision for a human to make. This is the decision taken.

The decider stated the rule directly: *"When I am approving someone to read my messages in a room I am
also approving them to use any service that I have granted to that room."* And its converse, which is
the part that matters for security: *"if somebody joins the room and I don't know them and I haven't
approved them, then by definition even if I've shared a service in that room, that new person should not
know about that service."* Not merely be refused by it — **not know it exists.**

Three facts shape the rest of the design:

- **The host's consent set — not the room — is the unit of access control.** Membership is emergent
  (join + consent, ADR-007), and the two halves are not equivalent: the join half is a secret and a
  proof of work, the consent half is a person deciding. Only the second is a basis for authorization.
  An earlier revision of this section asserted that "the room is already the unit of access control";
  that is the error decision 3 was built on.
- **Tor's address is its authorization; a `.vox` name is deliberately not.** Knowing a `.onion` is
  sufficient to connect. A `.vox` service name is only ever learned from inside a sealed envelope that
  only approved readers can open, and holding it confers nothing — so it can be pasted into a bug
  report without consequence. Vox is strictly better here without being harder to use.
- **Tor already solved "the unauthorized must not learn the service exists", and its answer transfers.**
  Client authorization in a v3 onion descriptor encrypts the introduction points to a set of client
  keys, one `auth-client` wrapper each (`/opt/tor` `hs_descriptor.c:9-52`, `:712`, `:1425`). An
  unauthorized client can fetch the descriptor and still learn nothing about how to reach the service.
  Decision 9 is that construction, with the room's log as the directory and the host's approved readers
  as the client set.

## Decision

### 1. The name is the service's own key

The capability is a **room-bound service**: a TCP service offered by a host *into a room*, reachable by
exactly those members of that room whom the host has approved to read its messages. What a person types
at a tool is the service's **`.vox` name**:

```text
<52-char-base32-of-service-public-key>.vox
```

Tor's construction, adopted as-is in substance: `/opt/tor` `hs_common.c:902` builds an address as
`base32(PUBKEY || CHECKSUM || VERSION)` where `PUBKEY` is the service's own ed25519 master identity
key. The name is the service — not the room, not the host's member fingerprint, and not a directory
entry.

**Why the service's own keypair**, rather than the cheaper alternative of a random 256-bit label signed
by the host's member key: a name that only its key holder can sign for is unambiguous everywhere with no
trust-on-first-use. The concrete attack the keypair closes: an approved reader of a service legitimately
learns its name `N`; with a mere label, nothing stops that reader publishing a descriptor for `N` in a
*different* room and being its host there, so a third party in both rooms sees two hosts for one name. A
keypair makes it impossible rather than detectable.

**Rejected: the channelID.** The previous revision named the service by its room
(`<channelID>.vox`), justified on the grounds that `(channel, port)` is what `TunnelRequest` already
carries. That coupling is what left a service added to a chat room **unnameable** — `node::resolver`
resolves a name to the room's *genesis creator*, which is only the host for a room `vox serve` created,
so it deliberately refuses to name any other room (`resolver.rs:27-30`). The good name and the sound
authorization ended up in different commands. A per-service key decouples them: every service gets a
name, in any room, under one authorization model.

**Rejected: deriving the name from room + host key + port.** No new key material, and reproducible —
but then anyone holding the room can compute the name by guessing the port, which discards the property
that a name is only ever learned from someone who was told it.

**No checksum.** Tor spends two bytes on one because a mistyped address is looked up remotely. Here a
typo decodes to a different 256-bit key, which names no service this client holds a descriptor for, so
it fails locally and immediately and cannot be misdirected.

"Tunnel" remains the name of the ADR-013 *mechanism* — one QUIC stream splicing one TCP connection. A
room-bound service is the thing a person offers; a tunnel is how a byte gets there.

### 2. Nothing is ever exposed implicitly

Every service is **explicitly declared** before it can be reached, and declaration is separate from
authorization. A local port becomes reachable only when a human names it, and only to identities that
human has approved. The overlay carries arbitrary TCP, so a node that exposed a local port as a side
effect of any other action would be a foot-gun of the first order.

The previous revision carried the clause "and only to identities a human *(or rule 3)* authorized". That
parenthesis is withdrawn: there is no longer any path by which a service becomes reachable without a
human having approved the specific identity reaching it.

### 3. Consent is the authorization

**A service bound to a room is reachable by exactly the members of that room whose keys its host has
approved for reading, and by nobody else.** One decision, made once per person, covering messages and
services together.

Precisely:

- The gate is `readers_of(host)` **within the bound room** — the ADR-007 per-sender consent set the host
  already maintains. Not the room's author set, not its member count, not anything derived from the
  passphrase or the proof of work.
- Approving a reader takes effect **immediately** and needs no second act. A host with five approved
  readers who then binds a service has, in that moment, given all five reach.
- Withdrawing approval takes effect immediately and tears down live connections (decision 10).
- **A service bound to two rooms** is reachable by the union of the host's approved readers in each. The
  name is stable across them; one descriptor is published per (service, room), each sealed to that
  room's approved readers.

#### What this withdraws

| Withdrawn | Was | Why it goes |
|---|---|---|
| **Genesis service grant** (`GenesisBody::service_grant`) | capabilities conferred on every admitted member, no certificate issued | admission is a secret + a proof of work, not a human decision; this made every syncing peer's author set into an access list |
| **`service-grant-exclusion` (`0x0013`)** | per-member revocation of the above | it exists only to revoke a grant that will not exist. It is also the mechanism behind finding #5 (a new epoch clears every exclusion, `governance/servicegrant.rs:37`), so withdrawing it closes that finding rather than fixing it |
| **`vox grant <room> <member> <tag>`** | an explicit per-member, per-service capability on the log | redundant under consent, and a second authorization surface that can drift out of step with the first — which is the bug class of finding #1. Selectivity finer than "my approved readers in this room" is expressed by using a second room |
| **`vox serve` creating a room** | one command created a room, set the grant and minted an invite | a service now binds to a room that already exists, so there is no genesis to write a grant into |
| **`Evaluator::build_with_members(authors.keys())`** | the genesis grant evaluated over every admitted author (`channel.rs` `build_evaluator`) | this is finding #1's proximate cause |

#### What the decider gives up, stated plainly

Reach can no longer be granted to a non-member, and it can no longer be narrowed below "my approved
readers in this room". Both were possible with `vox grant`. The trade is deliberate: one authorization
surface that cannot disagree with itself, against two that can. An infosec reviewer will ask whether a
host can share `:22` with two of its five approved readers; the answer is *no, use a second room*, and
that answer is a design position rather than an omission.

#### What it does not change

Vouching remains a bug in its own right, independently of services. There is no capability by which one
member adds another: a joiner must hold the room magnet link and the passphrase, and `learn_members` /
`admit_author` must stop creating members from a peer's board records on a self-signed record alone.
Consent-bound services make that bug non-escalating; they do not make it acceptable.

### 4. Two commands, and the service name

**Host.** The room already exists — a chat room, an agent room, any room the host is in. One command
binds a local port into it:

```
$ vox serve a3f9c2 22
service    h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq
name       h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox
room       a3f9c2… (design-review)

serving 127.0.0.1:22 to 3 of 5 members — the 3 whose keys you have approved.
  2 members are not approved and will not learn this service exists.
^C to stop.
```

The host hands the guest the **name**, in the room, sealed (decision 9) — so in the common case the host
hands over nothing at all: an approved reader's client already holds the descriptor and can list the
service by name. There is no invite to mint and no passphrase to generate, because the guest is already
a member.

**Guest.** Nothing to join, because they are already in the room. The service is reached by its name, at
its port, by any ordinary tool:

```
$ vox service list a3f9c2
h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox  :22   alice

$ ssh user@h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox
```

`vox up` (decision 5) is what makes the last line work, together with one `ProxyCommand` line in
`~/.ssh/config` that `vox up` prints — written once for every room there will ever be.

#### The port names the service within the name

There is no tag for a person to invent, share or remember. `vox serve <room> 22` offers the serving
machine's own `127.0.0.1:22`, and the connecting machine reaches it on **port 22 of the `.vox` name** —
the port the tool would have used anyway. The two are the same number by default and need not be:
`vox serve <room> 22 --at 10.0.0.5:2222` covers the case where the local endpoint differs. ADR-013's
`TunnelRequest` already carries a free-form `service_tag: String`, so the tag is the port in decimal;
this remains a UX decision with **no wire change**.

**One name, many ports.** Tor's shape (`HiddenServicePort`, several lines under one service key), and
adopted for the same reason: the name identifies the service, the port selects an endpoint inside it.
`vox serve <room> 22` followed by `vox serve <room> 8080` binds both under one name and one descriptor.
Everything under one name therefore shares one consent set — which is exactly the intended semantics,
since the consent set is the host's approved readers either way.

**Naming a service is not creating a room.** `vox serve` no longer mints rooms, passphrases or invites.
A room whose only purpose is one service is made explicitly (`vox room new`, then `vox serve`), so the
combined form's foot-gun — an address plus a passphrase being sufficient for reach — has nothing to
stand on.

Rules the surface must honour:

- **`vox serve` reports its audience and its non-audience.** The count of approved readers who can reach
  the service, and the count of members who cannot, on the line that confirms it is serving. A host
  should never have to ask who can reach the thing it just shared.
- **`vox serve` refuses to start rather than appear to work.** If the host cannot be reached and has no
  anchor configured, it says so and says what to do, instead of naming a service nobody can reach.
- **The service key is persisted**, in the profile directory, so the name survives a restart. A lost key
  is a lost name; there is deliberately no recovery path, because the alternative is deriving the key
  from something guessable.

### 5. One local entry point: a SOCKS5 proxy (`vox up`)

> **`vox up` runs a SOCKS5 proxy on `127.0.0.1:1080`.** It resolves `.vox` names itself — the client
> sends the name, not an address (`socks5h`) — and carries the connection to the room's host as a tunnel,
> with the port as the service tag. ADR-013's SOCKS5 front-end (`tunnel::socks`, RFC 1928, already coded
> and tested including the hostname address type) is the implementation.

**This is what Tor does, and Tor is the thing being replaced.** That is the argument, and it is recorded
from the source rather than from memory (`/opt/tor`, `doc/man/tor.1.txt`) so it is not re-litigated:

| Tor mechanism | What it costs |
|---|---|
| `SocksPort` | nothing privileged; the tool must be proxy-aware, which is why `torify(1)` ships in the tree as "a wrapper that calls torsocks" |
| `DNSPort` + `AutomapHostsOnResolve` | "we map an unused virtual address to that address, and return the new virtual address… handy for making '.onion' addresses work with applications that resolve an address and then connect to it" |
| `TransPort` | "requires OS support for transparent proxies, such as BSDs' pf or Linux's IPTables" |

**Tor has no network interface at all** — no TUN, no `utun`, no kernel device anywhere. And there is no
mechanism in it that makes plain `ssh user@<id>.onion` work with nothing configured; that is precisely why
`torsocks` exists. So the honest statement of the cost, rather than a design that engineers around a
guarantee nobody offers:

- **`ssh` needs one `ProxyCommand` line**, matched on `*.vox`, written once for every room there will ever
  be. `vox up` prints it. Most other tools take the standard `ALL_PROXY=socks5h://127.0.0.1:1080`.
- **Nothing needs privilege, on any platform, ever** — no device, no route, no firewall rule, no port below
  1024, no resolver entry. A person who cannot administer the machine they are using can still run this.
- Tools with no proxy support at all are served by `vox forward`, which binds a real local port.

The `h` in `socks5h` is load-bearing: it tells the client to send the hostname and let the proxy resolve
it. A `.vox` name has no meaning to the local resolver and must never be sent to one, so a client
configured for plain `socks5` fails before it reaches the proxy — the correct failure, if an opaque one.
The proxy refuses a literal-address CONNECT for the same reason it refuses an unknown name: this is not a
general-purpose proxy, and one on loopback that forwarded arbitrary addresses would be an open relay for
anything on the machine.

**A reversal, recorded because the reasoning is the useful part.** An earlier revision of this decision
specified a Vox *network interface* — a userspace TCP stack behind a `tun` device — on the grounds that it
is the only way an *unmodified* tool reaches the name. That is true, and it was still wrong: it is heavier
than anything Tor does, it puts a privileged install step in front of "try Vox", and it was chosen without
first checking what the thing being replaced actually requires. The interface was built, gated, and
removed. If zero-per-tool-configuration is ever wanted it is the same ladder Tor offers — automap plus a
transparent proxy, or an interface — and it is an *addition* for someone willing to pay firewall rules for
it, never the primary path.

Accordingly the `.vox` name resolves **inside the proxy**, from rooms this machine has joined, and no DNS
is involved at all: `node::resolver` maps the name to a room and its host, and there is nothing for a
resolver to answer because SOCKS5 carries the hostname itself.

### 6. The carried session has no IP addresses of its own

`ssh` over Vox runs at a different layer from the network the two machines share, and the consequence is
the one worth stating plainly: **neither machine's real address appears anywhere in the port-22
conversation.**

| Vantage point | The port-22 flow looks like |
|---|---|
| connecting machine, loopback | `127.0.0.1 → 127.0.0.1:1080` — the tool talking to `vox up`, carrying the `.vox` *name* and the port, never an address |
| serving machine, loopback | `127.0.0.1 → 127.0.0.1:22` — Vox dials the local endpoint the host declared |
| the `sshd` process itself | a peer of `127.0.0.1`; the client's address is not in its logs, in `last`, or in `who` |

The two real addresses do exist — but on a **different flow at a different layer**: one UDP/QUIC
association between the two Vox nodes. That flow carries no port 22, no channelID, no service tag and no
identity in cleartext: SNI is the constant `vox.invalid`, ALPN names only the protocol, and TLS 1.3
encrypts both identity certificates, so not even a fingerprint is on the wire. ADR-013's
`TunnelRequest{channel_id, service_tag}` and every carried byte are stream frames inside it. **No packet
anywhere pairs a real address with the service's port.**

**Vox knows exactly who is calling — the service is simply not told by an address.** Identity at the Vox
layer is at *key* level and is per room: `tunnel::session::accept` holds the client's composite
fingerprint, pinned by the ADR-011 handshake, together with the channelID it claimed, and checks it
against the host's approved-reader set for that room (decision 3) **before any local connect**
(ADR-013). That is strictly better evidence than an address — unspoofable, not shared by a NAT, and
withdrawable per member.

What does not reach the carried service is that identity, because every Vox client arrives at it from
`127.0.0.1`. Two consequences follow, and both are recorded rather than discovered later:

- **IP-based controls on the service are inert** for Vox clients (`sshd` host patterns, `hosts.allow`,
  `fail2ban`, anything reading a peer address). They are also redundant: an address was always a weak
  stand-in for identity, and the host's ADR-007 per-sender consent set — which it maintains anyway and
  can withdraw at any moment (decision 10) — is the strong form of the same control.
- **Attribution is Vox's job, not the service's logs.** The node holds `(room, client fingerprint)` at the
  gate, so it can say who reached what; surfacing that — as an event and in the client — is part of M17.7,
  because an authorization that cannot be audited is half an authorization. Nothing is prepended to the byte
  stream and no credential is minted for the carried protocol: this ADR's Non-goals forbid both, and the
  reason stands — a second auth scheme per service is overhead for a weaker outcome.

**Non-goal: IP-level anonymity.** The two nodes' addresses are visible to each other and to an on-path
observer whenever ADR-012's ladder finds a direct path — which it prefers, because the alternative is the
relay operator's bandwidth on every byte for the life of the room. Vox hides *what* is reached, *which
room* authorized it, and every Vox *identity* involved; it does not hide *where* the parties are. A
relay-mandatory mode was specified in an earlier revision of this ADR and reverted, because it bought a
guarantee this project does not make at a permanent bandwidth cost. What remains is the quasi-anonymity a
keys-not-accounts system gives: an observer sees two addresses speaking Vox, never a fingerprint, a room,
a service or a name. Anything needing location anonymity composes Vox over Tor, and nothing here prevents
that.

Volume and timing remain visible on the outer association, as for any tunnel; ADR-009's deniability work
is where padding belongs if it is ever wanted.

### 7. The anchor is configuration, not an argument

`--anchor <fp>@<addr>` on every command is the second-worst step. Anchors become **configuration**:

- `vox node` writes its own anchor spec to `<config_dir>/anchors` when it starts, so a client on the
  same machine needs no flag at all;
- a remote anchor is one line in that file, written once;
- `--anchor` remains, for overriding and for scripts.


### 8. How many steps this actually is

Stated honestly, side by side with the thing being replaced, and counting the guest as well as the host
— because a surface that moves work from the host onto the guest has not removed it.

| | Tor private service | Vox room-bound service |
|---|---|---|
| **host, once** | two `torrc` lines, restart, read the `.onion` | `vox serve <room> 22`, read the name |
| **host, per guest** | — | — (the host already approved them to read; decision 3) |
| **guest, once per machine** | `ProxyCommand` for `*.onion`, or `torsocks` | `vox up`, plus a `ProxyCommand` for `*.vox` that `vox up` prints |
| **guest, once per room** | — | already a member — nothing |
| **guest, per use** | `torsocks ssh user@<id>.onion` | `ssh user@<id>.vox` |

The per-use line and the one-time setup are **identical in kind and in effort** to Tor's, because they
are the same mechanism for the same reason (decision 5). The guest's "once per room" line is now empty,
where the previous revision had `vox connect` plus a passphrase: binding a service to a room the guest is
already in removes the join from the service flow entirely. What Vox's guest has that Tor's does not is
that the host approved them individually — and that is the second factor and the revocability Tor has no
equivalent of, obtained at zero additional steps because the host made that decision already.

For the case where host and guest share no room, there is no service flow: they make a room first. That
is one more step than Tor and it is where Tor's model is genuinely cheaper. The trade is decision 3's.

The host side varies with reachability, because the ADR-012 ladder is not uniform:

| The host is | Extra host step | Why |
|---|---|---|
| publicly reachable, or behind a router that granted a port map (UPnP/PCP/NAT-PMP, ADR-012 rungs 1–2) | none | peers reach the host's own address; no anchor involved |
| behind a cone NAT | none | rung 3 hole-punches, proved against real NAT behaviour (ADR-016 M14.9) |
| behind a symmetric NAT at **both** ends | one anchor line in the config file, once | rung 4 relays, and a relay must exist somewhere and be named |

The common home-router case is therefore at parity with Tor on both sides. Only symmetric-NAT-on-both-ends
makes the anchor load-bearing for carried traffic, and Tor has thousands of volunteer relays to draw on
where Vox deliberately has none but yours (ADR-012: no Vox-operated infrastructure).

### 9. The descriptor: one sealed envelope per (service, room)

A host publishes a **service descriptor** to the room's log: a signed entry carrying the service's name
and how to reach it, sealed so that **only the host's approved readers in that room can open it**.

This is Tor's client-authorized descriptor with the room's log substituted for the HSDir ring. The
construction being followed (`/opt/tor` `hs_descriptor.c:9-52`):

| Tor | Vox |
|---|---|
| HSDir hash ring — third parties holding a blob they cannot read | the room's log — synced by members, sealed to approved readers |
| superencrypted layer, keyed off the blinded pubkey (only those told the address can open it) | **not reproduced** — see below |
| inner encrypted layer, holding the introduction points | the descriptor body: the service name, its ports, and the host's overlay address |
| one `auth-client <client-id> <iv> <encrypted-cookie>` per authorized client (`:712`), cookie wrapped under `KDF(subcredential ‖ x25519(service_sk, client_pk))` (`:1425`) | one wrapper per approved reader, under the ADR-006 per-recipient sealing the channel already uses for SKDMs |

**Only one layer, deliberately.** Tor needs two because its carrier is untrusted: an HSDir is a stranger,
so the outer layer stops it reading what it stores, and knowing the address is what opens it. Vox's
carrier is the room's own log, which only members sync, and the payload is already sealed per approved
reader — so **the name travels inside the same envelope as the reach information.** There is no second
layer to add, because there is no party who holds the descriptor, lacks approval, and knows the name.

The consequence is the property stated in decision 1: **a `.vox` name is not a bearer capability.** A
reader who has the name and loses approval has nothing. A name pasted into a bug report, a shell history
or a support ticket grants no reach to anyone. Enforcement is the consent check at dial time and the
sealing of the descriptor — never the secrecy of the string.

What an unapproved member of the room sees: an opaque sealed entry on the log, of a size that reveals the
audience count and nothing else. Not the name, not the ports, not that it is a service descriptor rather
than any other sealed entry. This satisfies the decider's converse rule exactly.

**Freshness rides the host's `chain_id`, not the channel epoch.** Log records are durable, so a revoked
reader keeps the last descriptor it could open. The descriptor therefore names the generation it was
published under, and is republished when that generation advances.

The generation is the **host's own ADR-006 `chain_id`**, because that is the counter consent revocation
already moves: ADR-007 specifies that revoking outbound consent generates a fresh sender key and advances
*"`A`'s own `chain_id`* (the per-author generation counter, ADR-006) — **not** the channel `epoch`"*, then
distributes the new key to every member `A` still consents to. A descriptor stamped with the host's
`chain_id` and re-sealed on the same event is therefore republished by exactly the act that changes the
audience, to exactly the audience that remains — and the sealing work is the SKDM distribution that
already happens.

*Recorded because the decision was taken on a wrong premise and corrected before any code:* the decider
chose "tie it to the room epoch" from options that asserted revocation triggers an epoch bump. It does
not — a channel epoch advances only on a passphrase rotation, a far rarer and heavier event, and hanging
descriptor freshness on it would leave a revoked reader's descriptor valid until someone rotated the
room's passphrase. The stated intent (freshness from the revocation signal that already exists, no timers,
no periodic writes) is what `chain_id` delivers.

No timers and no periodic writes either way: Tor's 180-minute `descriptor-lifetime`
(`hs_descriptor.c:14`) exists because its descriptors live on strangers' disks with no revocation channel,
and Vox has one.

**This also dissolves a dependency.** Hanging freshness on the channel epoch would have made finding #5 —
a new epoch clears every service-grant exclusion (`governance/servicegrant.rs:37`) — a blocking
prerequisite. Keyed to `chain_id` it is not: finding #5 concerns the epoch clearing exclusions of a
genesis grant, and decision 3 withdraws both. It remains a real bug in the governance module and is fixed
on its own merits (M17.8), not as a precondition here.

The rejected alternative remains rejected, for the same reason and now with a second: a room-wide
plaintext announcement tells members who cannot reach a service that it exists — a standing inventory of
what each member runs, published to everyone, for no benefit to anyone who can use it; and under decision
3 it would leak the *name*, which is the one string the unapproved must not have.

Discovery is **convenience, never authorization**. Holding a descriptor never grants reach; the consent
check in `tunnel::session::accept` remains the only gate.

### 10. Withdrawing approval is immediate, and says so

Un-approving a reader:

1. **tears down that reader's live connections at once** — an `ssh` session dies mid-keystroke;
2. **tells the other end why**: the client reports *access withdrawn by \<host\>*, rather than closing as
   though the network had dropped;
3. republishes the descriptor without that reader's wrapper, on the epoch bump;
4. refuses every subsequent dial at the consent check, independently of 3 — because a reader who cached a
   descriptor it could once open must not be reachable on the strength of that cache.

Points 1 and 4 are the enforcement; 3 is hygiene. Point 2 is a deliberate choice to hand the revoked
party a clear signal rather than an ambiguous failure: the alternative — a silent close indistinguishable
from a network drop — was considered and rejected by the decider. It leaks the fact of revocation to
someone who can infer it anyway, and an ambiguous failure invites the revoked party to keep retrying,
which is worse for both sides.

A host that withdraws approval and later restores it has restored service reach as well, in the same act.
There is no separate service state to remember, because there is no separate service authorization.

## Non-goals

- **No new authentication scheme for the service being carried.** Vox routes and authorizes *reach*;
  the service authenticates its own users exactly as it always did. `ssh` keeps its keys, HTTP keeps
  its cookies, Postgres keeps its passwords. Adding a Vox-issued credential for every carried protocol
  would be large surface for weak gain, and a second trust root in a system whose whole point is one.
  ADR-013's SSH certificate authority is narrowed accordingly (see Links).
- **No implicit exposure.** See decision 2.
- **No authorization derived from membership.** See decision 3. Joining a room, holding its passphrase,
  paying its proof of work, or being admitted as an author on any peer's board confers **no reach**.
- **No room-wide plaintext service announcements.** See decision 9.
- **No service reachable by a non-member.** There is no anonymous access tier and no "public" service. A
  host who wants the world to reach something should use a web server.
- **No name that is a capability.** See decisions 1 and 9. Vox deliberately does not reproduce Tor's
  property that holding an address is sufficient to connect.
- **No IP-level anonymity, and no relay-mandatory mode to buy it.** See decision 6.
- **No global namespace, and no name resolution off the machine.** A `.vox` name is a service public key
  in base32; it resolves only inside a client holding a descriptor it could open, from data it already
  has. There is no directory, no registration, no DNS suffix to own, nothing to squat and nothing to
  enumerate. Vox will not publish a `.vox` resolver and will not ask for the TLD to be delegated.
- **No privilege, anywhere, ever.** `vox up` is an unprivileged loopback proxy: no device, no route, no
  firewall rule, no port below 1024, no resolver entry (decision 5).

## Consequences

### Positive
- **One authorization surface.** Reading and reaching are the same decision, so they cannot disagree.
  The class of bug that produced findings #1 and #5 — a second surface drifting from the first — has
  nowhere to occur.
- **Step six is gone without a new mechanism.** No credential, no genesis field, no log entry kind for
  authorization, and no additional human decision. The approval already existed.
- Every service gets a real name, in any room — the coupling that left chat-room services unnameable
  (`resolver.rs:27-30`) is dissolved.
- A member the host has not approved cannot learn that a service exists, which is Tor's client-auth
  property obtained from machinery the channel already has.
- The `.vox` name is safe to handle: it can be logged, pasted and shared without conferring reach.
- Nothing about the carried protocol changes, so any TCP service works on day one.
- The entry point needs no privilege of any kind (decision 5, unchanged).
- The carried session has no IP addresses of its own (decision 6, unchanged).

### Negative
- **Host and guest must already share a room.** Handing a service to someone you have no room with is
  two flows, not one: make a room, then serve. This is the step Tor genuinely does not have, and the
  previous revision's one-command answer to it is what proved unsound.
- **Reach cannot be narrowed below "my approved readers in this room".** A host wanting two of five uses
  a second room. Stated as a design position in decision 3.
- **Reach cannot be granted to a non-member at all.** `vox grant`'s one irreplaceable use disappears.
- **A service key is a new thing that can be lost.** Lose it and the name is gone; there is no recovery,
  because any recovery path implies a derivable key.
- **Per-recipient sealing makes the audience size visible** even when its contents are not — inherent to
  the construction, as ADR-006's SKDM already is.
- **Immediate teardown means the service layer watches consent.** Open streams must be reachable from a
  consent change, which is machinery that did not previously need to exist.
- A tool has to be told about the proxy once (`ProxyCommand`, `ALL_PROXY`). Same as a Tor user.
- A tool with no proxy support (`psql` is the honest example) uses `vox forward` and a local port.

### Neutral
- "Tunnel" narrows to mean the mechanism; existing ADR-013 text stays correct under that reading.
- `vox serve` keeps its name while changing its meaning, because the verb is right and the shape was not.

## Implementation plan

Each item is one branch, red→green, with the ADR updated in the same change (house rule).

**M17.1–M17.5 as previously written are superseded in part.** What was built and stands: the resolver's
and proxy's transport work (M17.3), anchors as configuration (M17.4). What was built and must be
**removed**: the genesis service grant and `0x0013` (M17.1), and `vox serve`'s room creation (M17.2).

- **M17.1 — *superseded.*** `GenesisBody::service_grant` and `service-grant-exclusion` (`0x0013`) are
  withdrawn by decision 3. Their seven golden vectors go with them; the wire tag `0x0013` is retired and
  not reused.
- **M17.2 — *partly superseded.*** `vox connect` stands (joining a room from an address is a real verb
  with its own uses). `vox serve` is reshaped by M17.7.
- **M17.3 — *stands, with one correction.*** `node::up` and the SOCKS5 datapath are unaffected.
  `node::resolver` must resolve a **service name to a descriptor** rather than a channelID to a genesis
  creator. **The M17.3 gate (`node_m17_up_gate`) currently asserts the vulnerability**: it authorizes "a
  real ADR-007 evaluator against the genesis service grant with no certificate issued to anybody". That
  assertion inverts under decision 3 and the gate must be rewritten, not merely extended.
- **M17.4 — *stands.*** Anchors as configuration.
- **M17.5 — *superseded by M17.10.*** `0x000F` advertisements become the descriptor of decision 9.

New work, in dependency order:

- **M17.6 — admission requires a join.** `learn_members` / `admit_author` must stop creating members from
  a peer's board record on a self-signed record alone. Gate: a bundle record synced from a peer's board
  does **not** make its subject a member; the RED test
  `sec_vouched_key_gets_no_service_grant.rs` goes green. Closes finding #1's admission half.
- **M17.7 — consent is the authorization.** `build_evaluator` stops passing `authors.keys()`; the dial
  check keys off `readers_of(host)` in the bound room. `vox grant` and `GenesisBody::service_grant` are
  removed. `vox serve` takes a room and no longer creates one. Gate: a member the host has not approved
  is refused, an approved one reaches the service, and the transition happens on the approval alone with
  no second command.
- **M17.8 — the epoch is a sound revocation signal.** Finding #5: a new epoch must not resurrect a
  revoked member. Blocking prerequisite for M17.10.
- **M17.9 — the service keypair and its name.** Persisted per service in the profile directory; the name
  is `base32(pubkey)`; one name, many ports; `node::resolver` resolves name → descriptor. Gate: a name
  survives a restart, two ports share one name, and a name for a service this client holds no openable
  descriptor for does not resolve at all.
- **M17.10 — the descriptor.** One sealed envelope per (service, room), per-reader wrappers on ADR-006's
  sealing, stamped with the host's `chain_id` and re-sealed on the same event that advances it. Gate: an
  approved reader lists the service by name without being told it; an unapproved member of the same room
  sees an opaque entry and can determine neither the name, the ports, nor that it is a service descriptor;
  and a reader whose consent is withdrawn cannot open the next descriptor. Does **not** depend on M17.8.
- **M17.11 — immediate teardown.** Withdrawing approval closes live streams and reports the reason to the
  far end. Gate: a live `ssh` session through the overlay dies on the approval being withdrawn, the
  client prints the reason, and a subsequent dial is refused at the consent check even with a cached
  descriptor.

M17.6 and M17.7 are the two halves of finding #1 and are independent of the naming work; they should land
first and can land in parallel. M17.9 blocks M17.10. M17.11 depends on M17.7. **M17.8 blocks nothing here**
— it was a prerequisite only under the withdrawn epoch-stamped descriptor — but it is a verified finding
and is fixed regardless.

## Links
**Depends on**: ADR-005 (the invite and its passphrase separation), ADR-006 (per-recipient sealing, which
the descriptor reuses), ADR-007 (per-sender consent — now the authorization basis — and revocation),
ADR-012 (reachability, anchors), ADR-013 (the tunnel data path), ADR-016 (the node that runs it).
- **Restores an ADR-013 invariant this ADR had qualified.** ADR-013 holds that *"tunnel capabilities are
  never inherited from membership."* The previous revision carved out an exception for a room's immutable
  genesis; decision 3 **withdraws the carve-out**, so the invariant stands unqualified again. The path
  ADR-013 was guarding against — "join my chat" silently becoming "you are on my LAN" — is closed by the
  invariant itself rather than by an argument about immutability.
- Amends ADR-013 further: the SSH CA is narrowed to an optional later capability; the port-forward model
  is the specified one for a *tool-facing* forward; the SOCKS5 front-end is built and is the person-facing
  entry point (`node::up`). The TUN model stays optional there, and unbuilt.
- Leaves ADR-014 as it was: its privileged helper / `NetworkExtension` stays **conditional on a TUN
  interface that is not on this path**.
- Depended on by: ADR-014, ADR-015 (the clients surface these verbs).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
