# ADR-017 — Room-Bound Services (the Tor-hidden-service equivalent)

**Status**: proposed — not started (ADR-013 supplies the data path this builds on; the two-command
surface, the `.vox` name, capability-bearing rooms and audience-encrypted advertisements are specified
here)
**Date**: 2026-09-21
**Updated**: 2026-09-21 — the person-facing address is a **`.vox` hostname** and the local entry point is
a **Vox network interface** (`vox up`), because the criterion is that an *unmodified* tool reaches the
name; the SOCKS5 proxy first recorded here is superseded (decision 5). The service is named by its
**port**, which is a Vox-layer identifier, not a bound port on either machine.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: services, tunneling, ux, capability, discovery, hidden-service

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
(decision 7 counts both sides carefully). The author's stated intent for Vox is to *replace* a Tor
private service, so six steps against two is a product failure, not a rough edge. This ADR specifies the surface that closes the gap, and names the thing
being offered so the rest of the documentation can stop calling it "a tunnel".

Two facts shape the design:

- **The room is already the unit of access control.** Membership is emergent (join + consent, ADR-007);
  capabilities live in the room's log. There is no separate identity system to bolt a service onto, and
  there must not be one (see Non-goals).
- **Tor's address *is* its authorization.** Knowing a `.onion` is sufficient to connect; the service
  decides what to do with you afterwards. Vox can be strictly better — the passphrase is a second
  factor, and a host can revoke one guest without disturbing others — without being harder to use.

## Decision

### 1. The name

The capability is a **room-bound service**: a TCP service offered *inside a room*, reachable only by
members of that room who hold its `dial:` capability. The artifact a host hands out is a **service
invite** (a `vox://` link; the room passphrase travels separately, as always). What a person *types at
a tool* is the room's **`.vox` hostname** (decision 4). "Tunnel" remains the name of the ADR-013
*mechanism* — one QUIC stream splicing one TCP connection. A room-bound service is the thing a person
offers; a tunnel is how a byte gets there.

### 2. Nothing is ever exposed implicitly

Every service is **explicitly declared** before it can be reached, and declaration is separate from
authorization. This is already the behaviour (`vox service add`, then `vox grant`) and it is hereby a
decision, not an accident: the overlay carries arbitrary TCP, so a node that exposed a local port as a
side effect of any other action would be a foot-gun of the first order. A local port becomes reachable
only when a human names it, and only to identities a human (or rule 3) authorized.

### 3. A room may *be* an access list — capability-bearing rooms

The six-step flow's worst step is the sixth: the host must wait for the guest to appear and then grant
them something. That round trip is what Tor does not have.

A room's genesis may therefore carry a **service grant**: a set of capabilities conferred on *every*
identity admitted to that room. When a responder admits a new author (ADR-016's join), it issues the
ordinary ADR-007 admin certificate for those capabilities in the same step. The grant is a normal log
fact — it converges by sync, every member sees it, and it is revocable per member afterwards.

The authorization basis is exactly the basis on which the joiner became a member at all: they held the
room passphrase and paid the ADR-005 proof of work. The room's purpose *is* the service, so "may this
member dial it" and "is this person a member" are the same question, asked once.

This yields two shapes, and both are wanted:

| Shape | How it is made | Who may dial |
|---|---|---|
| **Service room** | `vox serve` — purpose-built for one service | every member, by the genesis |
| **Service in an existing room** | `vox service add` in a chat room, then `vox grant` | only members granted individually |

The genesis is the right home for the rule: it is immutable, self-validating (its hash is the
channelID), and every node that holds the room — including an anchor that is not a member — converges
on it from the genesis alone, with no governance history to fetch first.

### 4. Two commands, and a `.vox` hostname

**Host.** One command creates the room, offers the service, sets the service grant, and mints the
invite:

```
$ vox serve 22
room       f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q
address    vox://f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q?a=…&b=…
passphrase trombone-harbour-ninety-cinder
           ^ send this by a different channel than the address

serving 127.0.0.1:22. anyone who joins with both may reach it. ^C to stop.
```

**Guest.** One command joins and receives the capability; from then on the service is reached by its
name, at its own port, by any ordinary tool:

```
$ vox connect vox://f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q
passphrase: ************
joined. reachable as f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q.vox

$ ssh user@f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q.vox
```

`vox up` (decision 5) is what makes the third line work, and it is run once per machine, not per room.

#### The port names the service

There is no tag for a person to invent, share or remember. `vox serve 22` offers the serving machine's
own `127.0.0.1:22`, and the connecting machine reaches it on **port 22 of the `.vox` name** — the port the
tool would have used anyway. The two are the same number by default and need not be: the port in a `.vox`
address is a Vox-layer identifier that the serving machine translates to whatever local endpoint it
chose, so it collides with nothing and binds nothing (decision 5). ADR-013's `TunnelRequest` already carries a free-form `service_tag: String`, so the
tag of a port-named service is simply its port in decimal; this is a UX decision with **no wire
change**. `vox serve 22 --at 10.0.0.5:2222` covers the case where the local endpoint is not
`127.0.0.1:<same port>`, and `vox service add <tag> <endpoint>` remains for the
service-in-an-existing-room shape, where a name is more useful than a number.

#### The hostname is the channelID

```text
<52-char-base32-of-channelID>.vox
```

The channelID is the genesis hash (ADR-008), and `b32_encode` — lowercase unpadded RFC 4648, already
the CLI's rendering of every fingerprint (`node::link`) — makes it 52 characters. That is *the same 52
characters that already begin the invite link*, so the guest's client derives the hostname from the link
it just pasted, with no additional field anywhere. With `.vox` the whole name is 56 characters, inside
DNS's 63-octet label limit and shorter than a Tor v3 `.onion` (56 + `.onion`).

Chosen over the host's identity fingerprint because `(channel, port)` is precisely what the tunnel
request already carries, so a host serving port 22 in two different rooms is unambiguous — where
`(host, port)` would not be.

**The name is self-certifying, and there is no registry.** Resolution never leaves the machine:

1. the 52 characters decode to the 32-byte channelID — nothing is looked up to learn it;
2. the client holds that room, so it reads the host's identity from the room's own signed log;
3. the dial pins that identity in the ADR-011 handshake.

So the name commits to the room by hash, the room commits to the host by signature, and the handshake
commits to the key. There is no DNS query, no directory, no trust-on-first-use, and no global namespace
in which two people could contend for a name (see Non-goals). A name the client has not joined does not
resolve *at all* — resolution is private to the joiner, which is strictly more than Tor offers, where
any `.onion` is resolvable by anyone.

**No checksum.** Tor v3 spends two bytes on one because a typo in an address that is looked up must be
caught early. Here a typo decodes to a different 256-bit channelID, which names a room the client has
not joined, so it fails locally and immediately with "not joined" — it cannot be misdirected. Spending
characters to detect what already fails safely is not worth the length.

Rules the surface must honour:

- **The passphrase is never in the address.** ADR-005's separation is load-bearing (ADR-016 M14): a
  leaked address is a leaked rendezvous, not a leaked room. `vox serve` prints the two on separate
  lines and says plainly that they must travel separately. A single combined blob is **not** offered,
  because a convenience that halves the security of the primary use case is not a convenience.
- **The passphrase is generated, not chosen.** A service room's passphrase is machine-generated with
  enough entropy to stand alone against the ADR-005 online-guessing bound; a human-chosen one is the
  weak link in an otherwise strong chain, and nobody needs to remember this one.
- **`vox connect` prompts for the passphrase unechoed**, or reads it from a pipe. Never a flag.
- **`vox serve` refuses to start rather than appear to work.** If the host cannot be reached and has no
  anchor configured, it says so and says what to do, instead of minting an address nobody can use.

### 5. One local entry point: a Vox interface (`vox up`)

The criterion is exactly one thing: **`ssh user@<id>.vox` works, unmodified, with nothing configured in
`ssh`.** Everything below follows from that and nothing else.

The data path, with the two machines named unambiguously:

1. On the **connecting machine**, `ssh` resolves `<id>.vox` and opens TCP to the address it gets back.
   Vox owns that address, so the packets arrive on the Vox interface, and Vox terminates the TCP in
   userspace (`smoltcp`, ADR-013's stated choice).
2. **Over the Vox layer**, that stream is carried as one QUIC stream per TCP connection (ADR-013),
   authorized by `dial:<port>` against the room's evaluator (ADR-007).
3. On the **serving machine**, Vox connects to the local endpoint chosen when the service was declared —
   `vox serve 22` means its own `127.0.0.1:22`, where the real `sshd` is already listening.

**Nothing binds a port at either end.** The serving machine dials *out* to its own endpoint; the
connecting machine reads *packets*. The port in a `.vox` address is therefore a **Vox-layer
identifier**, translated at step 3 to whatever local endpoint the host picked — it behaves like a NAT
over the overlay, and it is entirely userland. 22, 65532, or anything else is the same to it, and
neither machine's port-privilege model is on the data path.

> **`vox up` brings up the Vox interface and answers `.vox` names.** It is the one local entry point,
> and the only mechanism that meets the criterion.

- **The address is ADR-013's identity-derived ULA**, already implemented and tested
  (`tunnel::addr::overlay_addr`): `0xFD ‖ high-120-bits(SHA-256("vox/ula/v1" ‖ pubkey))`. Self-certifying,
  allocation-free, and recomputable from the identity the ADR-011 handshake pins — so the address the
  kernel routes and the key the connection authenticates are the same fact.
- **Vox answers DNS for `.vox` and for nothing else**, on loopback: `<52-char-base32>.vox` → the `AAAA`
  of the member serving that room, read from the room's own signed log. A name for a room this machine
  has not joined is `NXDOMAIN`, so `ssh` says "could not resolve hostname" — the honest message, and no
  dial is attempted.
- **A room with more than one member offering the same port** is addressed per member, not by the room
  name; the room name resolves to the host that declared the service. That is the
  service-in-an-existing-room shape, and `vox forward <member>/<tag>` already covers it.

**A proxy cannot meet the criterion, which is why this reverses an earlier decision here.** This ADR
previously specified a SOCKS5 proxy on the grounds that it never needs privilege. That optimised the
wrong variable: a proxy has to be *told about* by every tool — `ProxyCommand` for `ssh`, `ALL_PROXY` for
`curl`, nothing at all for `psql` — and the requirement is zero configuration, not zero privilege. Per-name
loopback addresses fail the same test for a different reason: they need a privileged alias per address on
macOS, and they still leave Vox holding sockets instead of packets. The interface is the only mechanism
where an unmodified tool reaches a `.vox` name.

**What it costs, stated plainly: one privileged step at install, and none afterwards.** Creating the
interface, routing the ULA prefix, and registering the `.vox` resolver are privileged because they claim
an interface and a DNS suffix — not because of anything to do with ports. On Linux a persistent device
owned by the user (`ip tuntap add mode tun user <you>`, once) leaves `vox up` itself unprivileged
thereafter; on macOS it is the `NetworkExtension` ADR-014 already plans for. This is the same install a
VPN asks for, once per machine, and it buys every tool working with nothing configured, forever.

Where a machine genuinely cannot take the interface, `vox forward` (already shipped) still gives a local
port and the user types `ssh -p <port> user@127.0.0.1`. That is a worse experience, labelled as one — a
fallback, not a second supported design.

### 6. The anchor is configuration, not an argument

`--anchor <fp>@<addr>` on every command is the second-worst step. Anchors become **configuration**:

- `vox node` writes its own anchor spec to `<config_dir>/anchors` when it starts, so a client on the
  same machine needs no flag at all;
- a remote anchor is one line in that file, written once;
- `--anchor` remains, for overriding and for scripts.

### 7. How many steps this actually is

Stated honestly, side by side with the thing being replaced, and counting the guest as well as the host
— because a surface that moves work from the host onto the guest has not removed it.

| | Tor private service | Vox room-bound service |
|---|---|---|
| **host, once** | two `torrc` lines, restart, read the `.onion` | `vox serve 22`, read the address and the passphrase |
| **host, per guest** | — | — (the service grant is in the genesis, decision 3) |
| **guest, once per machine** | `ProxyCommand` for `*.onion`, or `torsocks` | `vox up` (install: an interface and a `.vox` resolver) |
| **guest, once per room** | — | `vox connect <address>` + passphrase |
| **guest, per use** | `torsocks ssh user@<id>.onion` | `ssh user@<id>.vox` |

The per-use line is where Vox is **better than the bar**, not level with it: a Tor user wraps or
configures every tool, and a Vox user does not. The trade is one privileged install against
per-tool configuration forever. Vox's guest also does two things Tor's does not: **join the room** and
**hold a passphrase**. Neither is overhead to be apologised for — they are the second factor and the
revocability that Tor has no equivalent of (decision 3's trade, and `Consequences`).

The host side varies with reachability, because the ADR-012 ladder is not uniform:

| The host is | Extra host step | Why |
|---|---|---|
| publicly reachable, or behind a router that granted a port map (UPnP/PCP/NAT-PMP, ADR-012 rungs 1–2) | none | the invite carries the host's own address; no anchor involved |
| behind a NAT that granted nothing | one anchor line in the config file, once | a relay must exist somewhere and be named |

The common home-router case is therefore at parity with Tor on both sides. When a relay is genuinely
required there is one extra step, and Tor has thousands of volunteer relays to draw on where Vox
deliberately has none but yours (ADR-012: no Vox-operated infrastructure).

### 8. Discovery: advertisements encrypted to the audience

A member who holds `dial:<tag>` should not have to be *told the tag* out of band. A host may therefore
publish a **service advertisement** to the room: a signed entry naming its service tags, sealed so that
only the members holding the matching `dial:` capability can open it (ADR-013's audience-encrypted
advertisement, struct tag `0x000F`).

The rejected alternative was a room-wide plaintext announcement. It was rejected because it tells
members who *cannot* reach a service that the service exists — which is a standing inventory of what
each member runs, published to everyone, for no benefit to anyone who can use it. An advertisement
readable exactly by those who could already connect leaks nothing they did not already have.

Consequences of choosing the encrypted form: a host that adds a member to the audience later must
re-publish, and the audience size is visible even when its contents are not. Both are acceptable; the
second is inherent to any per-recipient sealing (as ADR-006's SKDM already is).

Discovery is **convenience, never authorization**. Seeing an advertisement never grants reach; the
`dial:` check in `tunnel::session::accept` remains the only gate.

## Non-goals

- **No new authentication scheme for the service being carried.** Vox routes and authorizes *reach*;
  the service authenticates its own users exactly as it always did. `ssh` keeps its keys, HTTP keeps
  its cookies, Postgres keeps its passwords. Adding a Vox-issued credential for every carried protocol
  would be large surface for weak gain, and a second trust root in a system whose whole point is one.
  ADR-013's SSH certificate authority is narrowed accordingly (see Links).
- **No implicit exposure.** See decision 2.
- **No room-wide plaintext service announcements.** See decision 7.
- **No service reachable by a non-member.** There is no anonymous access tier and no "public" service:
  the room is the boundary. A host who wants the world to reach something should use a web server.
- **No global namespace, and no name resolution off the machine.** A `.vox` name is the channelID in
  base32; it resolves only inside a client that has joined that room, from data it already holds. There
  is no directory, no registration, no DNS suffix to own, nothing to squat and nothing to enumerate.
  Vox will not publish a `.vox` resolver and will not ask for the TLD to be delegated (decision 4).
- **No privilege on the data path, and none per use.** `vox up` claims an interface and a DNS suffix
  once, at install; after that nothing Vox does to carry a connection is privileged, and no port on
  either machine is ever bound (decision 5). A second privileged step — per room, per service, per
  connection — is out of scope by construction.

## Consequences

### Positive
- The primary use case is two commands, which is the standard the author set.
- The service grant is an ordinary log fact, so it converges by sync, survives restart, is visible to
  every member, and is revocable per member with the machinery ADR-007 already specifies.
- Non-members remain unable to reach anything, and members without the capability cannot even learn a
  service exists.
- Nothing about the carried protocol changes, so any TCP service works on day one.
- The address a person types is the string they were already given, at the port the tool already uses,
  and it certifies itself: there is no moment in the flow where a user must compare two fingerprints or
  trust a first sighting.
- Every tool works with nothing configured — including the ones that have no proxy support at all — and
  no port is ever bound on either machine, so a `.vox` service collides with nothing the host already runs.

### Negative
- A leaked address **and** passphrase together yield service access with no further human step. This is
  the deliberate trade for removing step six; the mitigations are that both must leak, that the
  passphrase is high-entropy and machine-generated, that a service room contains nothing but the
  service, and that revocation is per member.
- The service grant is in the genesis, so it cannot be changed for an existing room — a room created
  without one needs explicit grants forever. That is the correct direction of immutability (a room
  cannot silently become an access list), but it means `vox serve` and "add a service to my chat room"
  are genuinely different flows.
- A host that is unreachable still needs an anchor, and that is one step Tor does not have.
- `vox up` needs one privileged step per machine to claim an interface and a DNS suffix, so Vox cannot be
  fully set up by a person who administers nothing. That person still reaches every service through
  `vox forward` and a local port, with the address quality that implies. This is the deliberate cost of
  the "unmodified tool" criterion, and it is paid once rather than per tool.
- The interface needs a userspace TCP stack and per-platform plumbing (`utun`/`NetworkExtension`,
  `/dev/net/tun`), which is the largest single piece of engineering this ADR implies and the one most
  exposed to OS policy changes.
- Naming the service by its port means a host offering two services on one port in one room must fall
  back to `vox service add <tag>`. The port-named form is for the single-service room `vox serve`
  creates, which is the case being optimised.

### Neutral
- "Tunnel" narrows to mean the mechanism; existing ADR-013 text stays correct under that reading.

## Implementation plan

Each item is one branch, red→green, with the ADR updated in the same change (house rule).

- **M17.1 — the service grant.** A `service_grant` field in the genesis policy; the responder issues
  the certificate when it admits an author; the evaluator already handles the rest. Gate: a joiner who
  never received an explicit grant can dial the room's service, a joiner to a room without a service
  grant cannot, and revoking one member leaves the others working.
- **M17.2 — `vox serve` and `vox connect`.** The two commands, the port-named service, the generated
  passphrase, the unechoed prompt, the refusal-to-start when unreachable with no anchor. Gate: two
  commands, two machines, real bytes — the M16.1 gate re-expressed as the two-command flow.
- **M17.3 — `vox up`: the `.vox` name and the Vox interface.** Three parts, each independently gateable:
  (a) the resolver — `b32` channelID ↔ hostname, the room's host read off the log, `AAAA` = the ADR-013
  ULA, `NXDOMAIN` for a room not held; (b) the interface — device, ULA route, and a userspace TCP
  termination (`smoltcp`) that turns an inbound SYN into `session::dial(channel, port)`; (c) the
  per-platform privileged setup, owned by ADR-014. Gate: an **unmodified** client program reaches a real
  service *by name*, with nothing configured in that program, and a name for a room the client has not
  joined never reaches a dial.
- **M17.4 — anchors as configuration.** `<config_dir>/anchors`, written by `vox node`, read by every
  client; `--anchor` still overrides. Gate: a client on the anchor's machine needs no flag.
- **M17.5 — service advertisements (`0x000F`).** Audience-encrypted, published to the room, surfaced
  in the client. Gate: a member with the capability sees the tag without being told it; a member
  without it sees nothing and learns nothing.

M17.1 depends on nothing outstanding. M17.2 depends on M17.1 and on ADR-012's port mapping (done,
M15.1c) for the two-step case. M17.3 depends on M17.2 only for the printed hint; the resolver and the
listener can be built and gated first. M17.5 is independent of the rest.

## Links
**Depends on**: ADR-005 (the invite and its passphrase separation), ADR-007 (capabilities, consent,
revocation), ADR-012 (reachability, anchors), ADR-013 (the tunnel data path), ADR-016 (the node that
runs it).
- Amends ADR-013, in three places: the SSH CA is narrowed to an optional later capability; the
  port-forward model is the specified one for a *tool-facing* forward; and **the TUN interface is
  promoted from "optional" to the specified person-facing datapath** — ADR-013 listed it as an
  alternative to the per-stream SOCKS/forward model, and decision 5 makes it the one that carries
  `<id>.vox`. The SOCKS5 front-end stays an unfinished ADR-013 item, no longer on this ADR's path. It
  qualifies ADR-013's invariant that *"tunnel capabilities are never inherited from membership"*: they
  still never are, **except** where a room's immutable genesis says so at creation (decision 3). A room
  made without a service grant can never acquire one, so the path ADR-013 was guarding against — "join
  my chat" silently becoming "you are on my LAN" — remains closed.
- Amends ADR-014: its privileged helper / `NetworkExtension` is **load-bearing for the primary flow**,
  not an optional extra added "only where a TUN interface later" appears — `ssh user@<id>.vox` does not
  work without it. ADR-014 keeps ownership of the packaging, entitlements and notarization; this ADR owns
  what the interface is for.
- Depended on by: ADR-014, ADR-015 (the clients surface these verbs).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
