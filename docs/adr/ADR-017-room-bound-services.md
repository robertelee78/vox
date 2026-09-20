# ADR-017 — Room-Bound Services (the Tor-hidden-service equivalent)

**Status**: proposed — not started (ADR-013 supplies the data path this builds on; the two-command
surface, capability-bearing rooms and audience-encrypted advertisements are specified here)
**Date**: 2026-09-21
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

A Tor hidden service takes two: add two lines to `torrc`, read the `.onion` address. The author's
stated intent for Vox is to *replace* a Tor private service, so six steps against two is a product
failure, not a rough edge. This ADR specifies the surface that closes the gap, and names the thing
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
invite** (a `vox://` link; the room passphrase travels separately, as always). "Tunnel" remains the
name of the ADR-013 *mechanism* — one QUIC stream splicing one TCP connection. A room-bound service is
the thing a person offers; a tunnel is how a byte gets there.

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

### 4. Two commands

**Host.** One command creates the room, offers the service, sets the service grant, and mints the
invite:

```
$ vox serve ssh 127.0.0.1:22
room       : infra-ssh  (bq4f7x2m9k1p…)
address    : vox://bq4f…?a=…&b=…&r=…
passphrase : trombone-harbour-ninety-cinder
             ^ send this by a different channel than the address

serving. anyone who joins with both may reach 127.0.0.1:22. ^C to stop.
```

**Guest.** One command joins, receives the capability, binds a local port, and prints the line to run:

```
$ vox connect vox://bq4f…
passphrase: ************
ssh -p 49213 user@127.0.0.1
connected. ^C to stop.
```

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

### 5. The anchor is configuration, not an argument

`--anchor <fp>@<addr>` on every command is the second-worst step. Anchors become **configuration**:

- `vox node` writes its own anchor spec to `<config_dir>/anchors` when it starts, so a client on the
  same machine needs no flag at all;
- a remote anchor is one line in that file, written once;
- `--anchor` remains, for overriding and for scripts.

### 6. How many steps this actually is

Stated honestly, because the reachability the ADR-012 ladder achieves is not uniform:

| The host is | Steps | Why |
|---|---|---|
| publicly reachable, or behind a router that granted a port map (UPnP/PCP/NAT-PMP, ADR-012 rungs 1–2) | **2** | the invite carries the host's own address; no anchor involved |
| behind a NAT that granted nothing | **3** | an anchor must exist somewhere and be named once in the config file |

Two steps in the common home-router case is Tor parity. Three when a relay is genuinely required is
one more than Tor — and Tor has thousands of volunteer relays to draw on, where Vox deliberately has
none but yours (ADR-012: no Vox-operated infrastructure).

### 7. Discovery: advertisements encrypted to the audience

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

## Consequences

### Positive
- The primary use case is two commands, which is the standard the author set.
- The service grant is an ordinary log fact, so it converges by sync, survives restart, is visible to
  every member, and is revocable per member with the machinery ADR-007 already specifies.
- Non-members remain unable to reach anything, and members without the capability cannot even learn a
  service exists.
- Nothing about the carried protocol changes, so any TCP service works on day one.

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

### Neutral
- "Tunnel" narrows to mean the mechanism; existing ADR-013 text stays correct under that reading.

## Implementation plan

Each item is one branch, red→green, with the ADR updated in the same change (house rule).

- **M17.1 — the service grant.** A `service_grant` field in the genesis policy; the responder issues
  the certificate when it admits an author; the evaluator already handles the rest. Gate: a joiner who
  never received an explicit grant can dial the room's service, a joiner to a room without a service
  grant cannot, and revoking one member leaves the others working.
- **M17.2 — `vox serve` and `vox connect`.** The two commands, the generated passphrase, the unechoed
  prompt, the refusal-to-start when unreachable with no anchor. Gate: two commands, two machines, real
  bytes — the M16.1 gate re-expressed as the two-command flow.
- **M17.3 — anchors as configuration.** `<config_dir>/anchors`, written by `vox node`, read by every
  client; `--anchor` still overrides. Gate: a client on the anchor's machine needs no flag.
- **M17.4 — service advertisements (`0x000F`).** Audience-encrypted, published to the room, surfaced
  in the client. Gate: a member with the capability sees the tag without being told it; a member
  without it sees nothing and learns nothing.

M17.1 depends on nothing outstanding. M17.2 depends on M17.1 and on ADR-012's port mapping (done,
M15.1c) for the two-step case. M17.4 is independent of the rest.

## Links
**Depends on**: ADR-005 (the invite and its passphrase separation), ADR-007 (capabilities, consent,
revocation), ADR-012 (reachability, anchors), ADR-013 (the tunnel data path), ADR-016 (the node that
runs it).
- Amends: ADR-013 (the SSH CA is narrowed to an optional later capability; the port-forward model is
  the specified one).
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
