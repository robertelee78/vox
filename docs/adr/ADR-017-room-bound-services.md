# ADR-017 — Room-Bound Services (the Tor-hidden-service equivalent)

**Status**: **revised — the authorization model of decision 3 is withdrawn.** Decisions 5, 6 and 7 are
built (`node::up`, `node::resolver`, and M17.4's `<config_dir>/anchors` as of 2026-09-22). An earlier
draft of this line claimed decision 7 shipped when it did not; it was corrected to "not built" by review
and is now genuinely built, with a real-binary proof. Decisions 1, 3, 4, 8, 9,
10 and 11 are **proposed and not built**; what ships today implements the withdrawn model and is a live
vulnerability until M17.6–M17.13 land.
**Date**: 2026-09-21
**Updated**: 2026-09-24 — PRD-001: forwards survive a host restart (ADR-013 "Tunnel honesty").
**Updated**: 2026-09-21 (third revision, then revised again the same day after independent review) —
**capability-bearing rooms are withdrawn.** Decision 3 held that *"'may this member dial it' and 'is this
person a member' are the same question, asked once."* That is refuted: admission to a room is passphrase +
proof-of-work, so under it any party who obtains an address and a passphrase — or, via the vouching path,
any party a single member syncs — is authorized to dial every service bound to that room. Authorization is
now **per-sender consent**, and consent is **per pair, per direction, and always an explicit human act**
(decision 3). The genesis service grant, its `service-grant-exclusion` (`0x0013`), the `vox grant` verb and
the `bind:` capability class are all withdrawn with it.

**Independent review round, 2026-09-21.** The first draft of this revision was reviewed by three models
before any code was written (`docs/adr/ADR-017-reviews/`). All three returned **REVISE**; all three agreed
the core direction is sound and verified it against the tree; all three found defects that would have
shipped. The material ones, and what changed:

- **Joining a room auto-consented to the responder.** `join` called `release_key_to(responder)` →
  `issue_consent` unconditionally (`node/actor.rs:1764`, `:1835`), and the responder is whichever member
  the board offers first (`:1603`) — influenceable by the link-giver and by a malicious anchor's ordering.
  So a host that joined through Mallory had consented to Mallory, and under `readers_of(host)` Mallory
  would have reached every service that host later bound. **This reintroduced the very hole the revision
  exists to close, through another door**, and no amount of fixing `learn_members` touches it. Found
  independently by two reviewers. Decision 3 now requires explicit consent in both directions and the
  automatic release is removed.
- **`bind:` was orphaned.** `add_service` checks `can_bind` (`node/channel.rs`'s `add_service`) and the only two
  sources of `bind:` were the genesis grant and `vox grant --may-bind` — both withdrawn, so `vox serve`
  would have worked for a room's creator and silently failed for everyone else. Found by all three.
  Resolved by deleting the capability: offering a local port of one's own machine is not the room's
  business (decision 3).
- **The name did not need a keypair.** Two reviewers independently proposed a host-committed random label,
  which blocks the same impersonation attack with nothing new to store or lose. It also removes a
  post-quantum inconsistency: 52 base32 characters carry 32 bytes, so a raw ed25519 service identity would
  have made the *name's* authentication classical in a system whose composite key is 1,984 bytes
  (`hash.rs:42`). Decision 1 changed.
- **A governance frame would have leaked the descriptor's existence.** Framed payload kinds are publicly
  classifiable to every log holder (`node/channel.rs`'s `classify_payload`), so a dedicated entry kind announces "a
  service descriptor is here" even with its body sealed — defeating the rule that an unapproved member must
  not learn a service exists. Decision 9 now publishes the descriptor as **content**.
- **Three claims about the tree were false** and are corrected in place rather than quietly dropped:
  decision 7's anchors-as-configuration (above); ADR-013's note that its m15 gate "was rewritten" when it
  still drives `NodeCommand::GrantTunnel`; and ADR-013's note that `vox grant` "is withdrawn" when it is
  still in `cli.rs:397`. Stating planned work in the past tense is the failure mode ADR-018 exists to
  prevent, and it happened three times in one change.
- **Two claims were corrections in my favour being refused.** `vox grant` could *not* reach a non-member
  (`node/actor.rs:2735` requires an admitted author), so the cost of deleting it was overstated — what is
  actually lost is time-bounded grants (`--days`) and reach-without-read. And verified finding #5 does not
  follow from the evaluator as claimed: exclusion resolution accumulates qualifying historical exclusions
  without filtering on the head epoch (`governance/evaluator.rs:519`, `:797`), so the ADR comment cited as
  evidence was not proof. Finding #5 is downgraded to **unverified** pending a test that exhibits it.

**The keyring question raised and settled 2026-09-21.** It was first recorded here as an open question —
how should the gate tell keyring-driven consent from a hand approval, given both call the same
`consent()` (`node/actor.rs:2045`)? It dissolves: the decider established that **approving a member in a
room *is* adding them to the ring**, so the ring is where every approval is recorded rather than a second
source to screen out. The gate is a conjunction — **in the host's ring AND in the room the service is bound
to** — and "explicitly approved readers" and "identities in the host's ring" name the same set. Node kinds
and a chat-versus-agent-comms context were both considered and rejected. See decision 3.

Descriptor freshness is keyed to the host's ADR-006 `chain_id` **and** to explicit publication triggers —
`chain_id` alone is insufficient because approving a reader does not advance it (`node/channel.rs`'s `issue_consent`),
which would have left a newly approved reader unable to open the standing descriptor. See decision 9, which
records why the decision as first taken was on a wrong premise.

Decision 5's SOCKS5 entry point and decision 6's addressless carried session stand as built, with one
correction noted in decision 5: `vox up` takes a single room and builds an immutable per-room resolver
(`vox-tui/src/cli.rs:332`, `node/actor.rs:2763`), which cannot resolve names that are now per-service and
cross-room. Calling decision 5 unaffected was wrong.
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

   It came with a trap, which review caught before any code: "the human decision already happened" is only
   true of consent a human *made*. The first draft of this revision keyed on the whole consent set, and the
   join path issues consent to the responder automatically — so the design would have inherited an
   authorization that no human ever granted. Decision 3 therefore states the requirement as **explicit**
   consent, in both directions, and M17.6 removes the automatic release.

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
  sufficient to connect. A `.vox` service name is only ever learned from inside a sealed envelope that only
  approved readers can open, and **holding it confers no reach**. It is not, however, *without consequence*
  — an earlier draft said so and review refused it: publishing a name discloses that the service exists and
  lets anyone who has seen it elsewhere correlate. "Not a bearer capability" is the claim; "harmless to
  leak" is not.
- **Tor already solved "the unauthorized must not learn the service exists", and its answer transfers.**
  Client authorization in a v3 onion descriptor encrypts the introduction points to a set of client
  keys, one `auth-client` wrapper each (`/opt/tor` `hs_descriptor.c:9-52`, `:712`, `:1425`). An
  unauthorized client can fetch the descriptor and still learn nothing about how to reach the service.
  Vox reaches the same end by a different means (decision 9): the descriptor is published as **content**,
  sealed to the host's consented readers by machinery that already exists, because a dedicated entry kind
  would itself announce that a descriptor is there (`node/channel.rs`'s `classify_payload`).

## Decision

### 1. The name is a host-committed random label

The capability is a **room-bound service**: a TCP service offered by a host *into a room*, reachable by
exactly those members of that room that are in its host's trust keyring. What a person types at a tool is
the service's **`.vox` name**:

```text
<52-char-base32>.vox   where the 32 bytes are  H("vox service name v1" ‖ host_composite_pk ‖ nonce)
```

`nonce` is 32 random bytes minted when the service is first offered and kept in the profile directory
beside it. It travels **inside the sealed descriptor** (decision 9) and nowhere else, so only the host's
approved readers ever learn it — and therefore only they can recompute the name.

**Why a commitment rather than a keypair.** The attack to close is impersonation: if a name were an
unconstrained random label and any host could publish "I serve N", an approved reader who legitimately
learned N could claim it under its own identity in another room, and a third party in both rooms would see
two hosts for one name. Binding the host's own composite public key into the name closes that — a reader
cannot substitute its own key and preserve N — and an unapproved member cannot guess the nonce. This is
what two independent reviewers proposed in place of the keypair the first draft specified, and it is
strictly better here for three reasons: there is no new private key to persist, back up or leak; the
construction reuses the composite signer that already exists; and it stays **post-quantum**, where a raw
ed25519 service identity in 32 bytes would have made the name's authentication classical in a system whose
composite public key is 1,984 bytes (`hash.rs:42`).

What the commitment gives up, recorded because it is a real loss: the name is bound to the host's identity,
so it cannot move to a different host and cannot outlive that identity. A service that must be portable
between machines would need the keypair form. No such requirement exists today.

**The descriptor must bind more than the name.** A commitment stops a reader minting a *new* claim on N; it
does not stop one **copying a genuine descriptor** into another room. So the signed descriptor body binds
name, host identity, room, ports and version together, and the client authenticates the transport peer as
that named host before carrying a byte — the check Tor makes explicitly when it verifies a descriptor's
signing-key chain against the key derived from the requested address (`/opt/tor` `hs_client.c:2198`). The
first draft left this validation contract implicit; it is decision 9's, and M17.12's gate.

**Rejected: the channelID.** The previous revision named the service by its room (`<channelID>.vox`),
justified on the grounds that `(channel, port)` is what `TunnelRequest` already carries. That coupling is
what left a service added to a chat room **unnameable** — `node::resolver` resolves a name to the room's
*genesis creator*, which is only the host for a room `vox serve` created, so it deliberately refuses to name
any other room (`node/resolver.rs:27-30`). The good name and the sound authorization ended up in different
commands. A per-service name decouples them: every service gets a name, in any room, under one model.

**Rejected: deriving the name from room + host key + port**, with no nonce. Reproducible and needing no
stored state — but then anyone holding the room computes the name by guessing the port, which discards the
property that a name is only ever learned from someone who was told it. The nonce is what makes the
commitment unguessable; without it the construction is a name, not a secret one.

**No checksum.** Tor spends two bytes on one because a mistyped address is looked up remotely. Here a typo
decodes to 32 different bytes, which match no descriptor this client holds, so it fails locally and at once
and cannot be misdirected.

"Tunnel" remains the name of the ADR-013 *mechanism* — one QUIC stream splicing one TCP connection. A
room-bound service is the thing a person offers; a tunnel is how a byte gets there.

### 2. Nothing is ever exposed implicitly

Every service is **explicitly declared** before it can be reached, and declaration is separate from
authorization. A local port becomes reachable only when a human names it, and only to identities that human
has trusted. The overlay carries arbitrary TCP, so a node that exposed a local port as a side
effect of any other action would be a foot-gun of the first order.

The previous revision carried the clause "and only to identities a human *(or rule 3)* authorized". That
parenthesis is withdrawn: there is no longer any path by which a service becomes reachable without a human
having approved the specific identity reaching it. Review established that the first draft of this revision
still had one — joining a room issued consent to the responder with no human act at all — which is why
decision 3 now states the requirement in both directions rather than assuming it.

### 3. The trust keyring is the authorization

**A service bound to a room is reachable by exactly those members of that room that are in its host's trust
keyring, and by nobody else.** One decision, made once per *identity* — not once per identity per room —
covering messages and services together.

#### Consent is per pair, per direction, and the *decision* is never automatic

The distinction that matters, because the delivery genuinely is automatic: **a consent grant may be
delivered by machinery, but it must always be *caused* by a human decision about that identity** — a ring
entry (ADR-007's invariant). The keyring's auto-consent is fine and necessary: the operator decided about
the key, and the node then delivers per room as rooms come and go. `join`'s release to the responder was
not, because nobody decided anything.

The decider's model, stated directly: *"Imagine there is already a room and there are four people in it and
they've all trusted each other. A new node joins. They will need to approve who they want to share with of
the people that are already in the room. Once they do that, when this new node writes something to the room
then the people that they approved should be able to read messages from the new node. However, of the people
already in the room, anything that they write will not be readable by the new node until the new node has
been approved by the existing node."*

So there are two independent decisions per pair, each made by the party giving something away:

| Decision | Who makes it | What it grants |
|---|---|---|
| "X may read **my** messages" — X enters **my** ring | me | X reads my entries in **every** room we share, now and later — **and reaches the services I bind to any of those rooms** |
| "I may read **X's** messages" — I enter **X's** ring | X | nothing of mine; it is X's grant to make, in X's ring |

Neither is implied by joining, by holding the passphrase, by paying the proof of work, or by being admitted
as an author on any peer's board. **A joiner who approves nobody is readable by nobody**, which is correct
rather than a defect: the joiner chooses, per person, and may well choose everyone.

**This required removing an automatic consent that shipped in v0.1.0.** `join` called
`release_key_to(&channel_id, responder)` unconditionally (`node/actor.rs:1764`), which calls `issue_consent`
— the same mechanism as explicit approval (`:1835`) — and the responder is *"the pinned responder, else any
member the board has an address record for"* (`:1603`). A host that joined through a member therefore
consented to that member with no human act, so under this decision's gate that member would have reached
every service the host later bound. The code's stated reason for the release was that *"the ADR-004
responder has no sending chain until it receives the initiator's first message, so until the joiner speaks
no member can answer at all"* — which is satisfied by the pairwise session, not by the sender key:
`ensure_session` builds the session from the board bundle record alone
(`Session::initiate(ring.identity_dh(), &record.prekey_bundle, …)`, `node/actor.rs:2509`) and the SKDM rides
*over* it. Removing the release therefore costs nothing functionally. M17.6.

#### The rest of the rule

- The gate is **(in the host's trust keyring) AND (in the bound room)**, checked at dial time. Not the
  room's author set, not its member count, nothing derived from the passphrase or the proof of work, and
  nothing consent-shaped that no ring entry caused — which is what the join path produced.
- Approving a reader takes effect **immediately** and needs no second act. A host with five approved
  readers who then binds a service has, in that moment, given all five reach.
- Withdrawing approval takes effect immediately and tears down live connections (decision 10).
- **A service bound to two rooms** is reachable by the union of the host's approved readers in each. The
  name is stable across them; one descriptor is published per (service, room), each sealed to that room's
  approved readers. Scoping stays **per room** at the dial gate — `tunnel::session` already names a channel
  and scopes endpoint lookup to it before authorizing (`tunnel/session.rs:245`), and that property must be
  preserved: a global host-wide reader union would break it.
- **The consent UI must say what it grants.** Approving a reader confers reach to every service that host
  has bound to that room, so the prompt says so. It is the one decision this entire design reuses, and a
  person making it must know its second effect. M17.7.

#### What this withdraws

| Withdrawn | Was | Why it goes |
|---|---|---|
| **Genesis service grant** (`GenesisBody::service_grant`) | capabilities conferred on every admitted member, no certificate issued | admission is a secret + a proof of work, not a human decision; this made every syncing peer's author set into an access list |
| **`service-grant-exclusion` (`0x0013`)** | per-member revocation of the above | it exists only to revoke a grant that will not exist. The wire tag is retired and not reused |
| **`vox grant <room> <member> <tag>`** | an explicit per-member, per-service capability on the log | redundant under consent, and a second authorization surface that can drift out of step with the first |
| **The `bind:` capability class** and `add_service`'s `can_bind` check (`node/channel.rs`'s `add_service`) | authority to *offer* a service, from the genesis grant or `vox grant --may-bind` | **binding a port of one's own machine is not the room's business.** Reach is what the room governs. Keeping `bind:` after withdrawing both its sources would have left `vox serve` working only for a room's creator — which review found, and which was an accident rather than a decision |
| **`vox serve` creating a room** | one command created a room, set the grant and minted an invite | a service now binds to a room that already exists |
| **`Evaluator::build_with_members(authors.keys())`** | the genesis grant evaluated over every admitted author (`node/channel.rs`'s `build_evaluator`) | this is finding #1's proximate cause |
| **Automatic consent on join** (`release_key_to(responder)`) | the joiner's sender key released to whoever answered the join | it is a reach grant issued with no human act, and the choice of recipient is influenceable |

#### What the decider gives up, stated plainly

Reach can no longer be narrowed below "the members of this room that are in my ring", and three capabilities
of `vox grant` go with it: **time-bounded** access (`--days`), **reach without read**, and authority over
who may *host*. Reach to a non-member was **not** among them — `vox grant` already required an admitted
author (`node/actor.rs:2735`), and the first draft of this revision overstated that loss.

Further, **only the host can cut a reader's reach.** With the genesis grant and `bind:` gone, a room admin
has no lever over another member's services; the room's only blunt instrument is a passphrase rotation
(decision 11). This is intended — a service belongs to the machine offering it — and is stated rather than
left to be discovered.

An infosec reviewer will ask whether a host can share `:22` with two of its five approved readers. The
answer is *no, use a second room*, and that is a design position rather than an omission.

#### Settled: the keyring *is* the approval, so there is one gate

**Decided 2026-09-21, after the open question this section previously held.** That question asked how the
services gate should distinguish keyring-driven consent from a hand approval, since both call the same
`consent(channel_id, target)` (`node/actor.rs:2045`). **The question dissolves**, because the decider
established that they are not two things:

> *"If I'm in a room and somebody joins and I approve them, that approval means I'm adding them to the
> ring."*

So the ring is not a second source of consent to be screened out — **it is where every approval is
recorded**. Two entry points reach it (a direct `vox trust add`, or approving a member in a room) and they
are two ways to make one decision (ADR-020 decision 3). Every entry in the ring got there by a human act,
so "the host's explicitly approved readers" and "the identities in the host's ring" name the same set.

**The gate is therefore a conjunction of two conditions, both checked at dial time:**

```text
reach(member, service)  ⟺  member ∈ host's trust keyring
                        ∧  member is in the room the service is bound to
```

The decider's own cases, which this must satisfy exactly:

| Situation | Reach |
|---|---|
| node-1 trusts node-2; node-1 serves service-1 in room-13; **node-2 joins room-13** | **yes, immediately**, with no further action by node-1 |
| node-3 joins room-13; node-1 has **not** trusted node-3 | **no** — and node-3 cannot learn service-1 exists (decision 9) |
| node-1 serves service-2 in room-8; node-2 is **not** in room-8 | **no** — trust is not enough; the room condition fails |
| node-1 trusts node-2; later both are in room-2; node-1 serves there | **yes** — no repeat of the trust dance, which is the point |

**Why the ring alone is not the gate.** Trust is room-independent, but a service is bound to a room, so
membership of that room remains a necessary condition. This keeps the per-room scoping that
`tunnel::session` already enforces (`tunnel/session.rs:245` names a channel and scopes lookup to it before
authorizing) and prevents the union-across-rooms reading that would break it.

**Why room membership alone is not the gate** is the whole of this revision: membership is a passphrase and
a proof of work, not a decision about a person.

**What keeps Signalgate closed**, in the decider's words: *"a random New York Times reporter joining a room
only grants them access if I know and trust that person too."* Joining is not an authorization event in
either direction.

**Not socially transitive.** A host never inherits identities from another ring. The decider drew this line
explicitly — *"I trust my son so much that anyone he has in his ring I also trust — I don't want to go that
far"* — and ADR-020 decision 3 already forbids transitive introduction and trust-on-first-use for the same
reason.

**Withdrawal.** Removing an identity from the ring cuts its service reach **immediately**, because the gate
reads the ring at connect time; live streams are torn down per decision 10. Its effect on *message*
readability is ADR-007's and requires changing the lock, which `Untrust` as built does not yet do.

#### No node kinds, and no chat-versus-agent-comms distinction

Both were considered on the way to the rule above and both are rejected. A node kind — human versus agent —
would hard-code a policy into an identity attribute rather than leaving it to the host's decision, and
nothing about a self-signed bundle record could make a claimed kind trustworthy anyway. A per-room context
(this is a chat room, that is an agent-comms room) was the decider's own first instinct and was withdrawn on
reflection: *"not a real distinction after all."* The same rule serves both, because in both the question is
only ever whether this host decided about this identity.

#### What it does not change

Vouching remains a bug in its own right, independently of services: there is no capability by which one
member adds another, and `learn_members` / `admit_author` must stop creating members from a peer's board
record on a self-signed record alone (M17.6). Review confirmed that an ordinary vouching peer **cannot**
insert itself into an existing host's consent set — consent verification binds the author fingerprint to the
signing key and resolution touches only that author's edges (`governance/consent.rs:184`,
`governance/evaluator.rs:754`) — so consent-bound services make vouching non-escalating. They do not make it
acceptable.

Nor is it a bypass that different nodes hold different views of a consent set. The serving host enforces its
own current state; a client's stale belief grants nothing.

### 4. Two commands, and the service name

**Host.** The room already exists — a chat room, an agent room, any room the host is in. One command binds a
local port into it:

```
$ vox serve a3f9c2 22
name   h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox
room   a3f9c2… (design-review)

serving 127.0.0.1:22 — reachable by the 3 members in your trust keyring:
  bob      k7m2q…x4
  carol    p9wnf…a1
  dave     z3hty…8c
not reachable by 2 members you have not trusted:
  erin     m4ksd…7j
  frank    q8xpl…2v   (they will not learn this service exists)

anyone you trust later, or who joins this room later, gains reach with no further action here.
^C to stop.
```

**Audiences are named, not counted.** The host sees *who*, on both sides. A count tells a person a number
when the thing they need to know is a list — and the whole model rests on the host understanding exactly
whom it has approved. Review flagged the first draft's `3 of 5 members` as insufficient and it is.

The host hands the guest nothing: an approved reader's client already holds the descriptor and lists the
service by name. There is no invite to mint and no passphrase to generate, because the guest is already a
member.

**Guest.** Nothing to join. The service is reached by its name, at its port, by any ordinary tool:

```
$ vox service list a3f9c2
h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox  :22   alice

$ ssh user@h4xm2qp7vk3nw8rtzc5jf9gd6bslyu2ae4mhq7pxv3nk8dwrt5cq.vox
```

`vox up` (decision 5) is what makes the last line work, together with one `ProxyCommand` line in
`~/.ssh/config` that `vox up` prints — written once for every room there will ever be.

#### The port names the service within the name

There is no tag for a person to invent, share or remember. `vox serve <room> 22` offers the serving
machine's own `127.0.0.1:22`, and the connecting machine reaches it on **port 22 of the `.vox` name** — the
port the tool would have used anyway. `vox serve <room> 22 --at 10.0.0.5:2222` covers the case where the
local endpoint differs.

**One name, many ports.** Tor's shape (`HiddenServicePort`, several lines under one service key), for the
same reason: the name identifies the service, the port selects an endpoint inside it. `vox serve <room> 22`
followed by `vox serve <room> 8080` **reuses the same nonce** and so the same name, adding a port to one
descriptor. Everything under one name therefore shares one consent set, which is the intended semantics
since the consent set is the host's approved readers either way.

**Nonce lifecycle, because "one name, many ports" depends on it.** A nonce is minted on the *first* `vox
serve` for a given (host, room) and reused for every later `vox serve` into that room. `vox service remove`
of the last port retires the nonce, and the next `vox serve` mints a new one — so a withdrawn service's name
does not silently come back to life pointing at something else. A host serving into two rooms has two
nonces and therefore two names, which keeps the per-room scoping of decision 3 visible in the address.

#### Two hosts, one port, is not a collision

Distinct hosts have distinct names, because the name commits to the host's key. But **`TunnelRequest`
carries `(channel, service_tag)` and not the name** (`tunnel/session.rs`), so the requested name must stay
bound to the tuple it is resolved into: the resolver records `name → (channel, host, port)` from the
descriptor it opened, the dial pins that host's identity in the ADR-011 handshake, and the tunnel request
carries the port as its tag. Nothing on the wire changes; the binding is the client's and is checked before
a byte moves. M17.12's gate covers rebinding and two hosts serving `:22` in one room.

**Naming a service is not creating a room.** `vox serve` no longer mints rooms, passphrases or invites. A
room whose only purpose is one service is made explicitly (`vox room new`, then `vox serve`), so the
combined form's foot-gun — an address plus a passphrase being sufficient for reach — has nothing to stand
on.

Rules the surface must honour:

- **`vox serve` names its audience and its non-audience**, as above.
- **`vox serve` refuses to start rather than appear to work.** If the host cannot be reached and has no
  anchor configured, it says so and says what to do, instead of naming a service nobody can reach.
- **The nonce is persisted** in the profile directory, so the name survives a restart. Losing it loses the
  name; there is no recovery path, because any recovery path implies a derivable — and therefore guessable
  — name.
### 5. One local entry point: a SOCKS5 proxy (`vox up`)

> **Correction, 2026-09-21 (review).** The proxy and its datapath stand as built, but `vox up` takes a
> single room and builds an immutable resolver from that room's genesis (`vox-tui/src/cli.rs:332`,
> `node/actor.rs:2763`). Names are now per-service and cross-room, and this decision promises one
> `ProxyCommand` "written once for every room there will ever be" — which a per-room proxy cannot honour.
> `vox up` must take **no room argument** and its resolver must span every descriptor this client can open
> (M17.3). An earlier draft of this revision called decision 5 unaffected; that was wrong.

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

> **Built 2026-09-22 (M17.4).** `vox node` writes the file and every command reads it; `--anchor`
> still works and **merges** rather than replaces, because anchors are additive and a person adding one
> on the command line rarely means "forget the configured one". An earlier draft of this revision listed
> the decision as shipped in v0.1.0 when it was not; it was then recorded as outstanding, and now it is
> done.
>
> **The file is machine-wide, which is what makes the decision work.** `Paths::resolve` puts
> `profile_dir` under the data root but takes `config_dir` from the config root, so
> `<config_dir>/anchors` is shared by every profile on the machine — one file written by `vox node`,
> read by every client. Building the proof is what surfaced this: the first version shared a *data*
> directory between two processes and failed with `Failed(Storage)`, because redb is single-writer. Two
> `vox` processes cannot share a profile; they share a machine.
>
> Details: one `<fingerprint>@<multiaddr>` per line, `#` comments and blank lines skipped so the file
> explains itself, rewritten whole on every address change (so a restart on a new port leaves no stale
> line to waste a dial on), written to a temporary file and renamed so a reader never sees it half
> written, and a malformed line is an error rather than silently skipped. It carries no secret — an
> anchor spec is a public identity and a public address.
>
> Gate: `crates/vox-tui/tests/anchors_config_proof.rs`, real binaries. `vox node` writes the file; a
> **different profile** on the same machine runs `vox serve` with no `--anchor` and its invite carries
> the anchor it learned from the file; a third profile runs `vox connect` with no `--anchor` and joins.
> Mutation-checked: stop reading the file and it fails.

> **Closed 2026-09-22: a running node now follows its anchor.** `vox daemon` re-reads its
> anchor configuration every 30s, re-resolves every spec and merges anything new; the
> existing `redial_anchors_if_due` then dials it. Two places discarded the new address and
> both had to go: `BootstrapSet::merge` and `ChannelState::add_anchors` both went through
> `add`, which keeps the first entry per identity — right for building a set, wrong for
> refreshing one, since an anchor that moved is the same identity at a new address. The
> channel one mattered independently: a channel's stored set is what an invite link
> carries, so a room made before the move would have handed out an unreachable address in
> every invite for ever. Gate: `crates/vox-tui/tests/a_daemon_follows_its_anchor.rs`, real
> binaries, mutation-checked on both halves. **Residual:** a name whose A record moves
> while the file is untouched is the same code path but is not measured — that needs a
> resolver the proof owns. The account of the gap as it stood follows.
>
> **A name is resolved once, at startup — known gap, 2026-09-22.** M17.5 let an anchor be named
> `home.example.us:4433` instead of `/ip4/.../udp/4433`, and the stated motivation was precisely that
> a person should not have to "re-issue it to every client when it moves — which for a home connection
> is whenever the ISP decides". The implementation does not yet deliver that for a **long-running**
> process. `resolve_host` has one call path, `parse_anchor_spec`, which runs when the CLI reads its
> configuration; nothing re-resolves afterwards. So `vox daemon`, `vox up` and `vox node` hold the
> address they got at launch, and when a home anchor's address changes they keep dialling the old one
> until someone restarts them. A short-lived command is unaffected, because it resolves and exits.
>
> This is a reachability failure that attributes badly — the anchor is up, the name is right, and the
> client says only that it cannot reach a peer — which is the exact complaint this decision exists to
> answer. It is recorded here rather than fixed in the same breath because the honest proof is the hard
> part: proving *re-resolution* rather than the proxy property "re-reads the file" needs a name whose
> record actually changes under the proof's control, and this machine has no such name. Closing it means
> both a re-resolve on the reconnect path and a prover that can move a record — a local resolver the
> proof owns, so the assertion is on the quantifier that matters.

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
| **guest, once per room** | — | already a member — nothing for the service; but see below |
| **guest, per use** | `torsocks ssh user@<id>.onion` | `ssh user@<id>.vox` |

The per-use line and the one-time setup are **identical in kind and in effort** to Tor's, because they
are the same mechanism for the same reason (decision 5). The guest's "once per room" line is now empty,
where the previous revision had `vox connect` plus a passphrase: binding a service to a room the guest is
already in removes the join from the service flow entirely. What Vox's guest has that Tor's does not is
that the host approved them individually — and that is the second factor and the revocability Tor has no
equivalent of, obtained at zero additional steps because the host made that decision already.

One honest addition, from decision 3's requirement that every direction be explicit: a guest who has only
just joined the room has an act of its own to perform — approving which members may read *it*. That is not
part of the service flow and grants the guest nothing, but it is work that the withdrawn model did
automatically, and a step count that omitted it would be the same kind of dishonesty this section exists to
avoid.

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

### 9. The descriptor is content, sealed to the host's ring

A host publishes a **service descriptor** to the room: an entry carrying the service's nonce (and so its
name), its ports and how to reach it, readable by **exactly those members of that room that are in the
host's ring**.

It is published as **ordinary content**, not as a governance frame. This is the change review forced, and
the reason is concrete: framed payload kinds are publicly classifiable to every holder of the log
(`node/channel.rs`'s `classify_payload`), so a dedicated descriptor kind announces *"a service descriptor is here"* even
with its body sealed — and an opaque payload is rejected by the classifier rather than carried. A governance
frame therefore cannot satisfy the rule that an unapproved member must not learn a service exists. Content
can: it is already sealed to the author's consented readers, so an unapproved member sees an ordinary entry
it cannot read and **cannot tell a service descriptor from a chat message**.

Publishing as content also settles three things the first draft got wrong or left open:

- **The sealing is existing machinery after all.** The first draft claimed the per-reader wrapper "is the
  SKDM distribution that already happens"; review correctly refused that, because ADR-006's sealing is
  live-session based and a log-published, open-later `auth-client`-style wrapper would have been new crypto.
  As content the point is moot — the descriptor rides the author's sender key, which is precisely the
  mechanism consent already governs. No new crypto.
- **The audience follows consent automatically**, including later approvals, because that is what content
  already does.
- **Freshness follows the same path as every other entry**, so a revoked reader cannot open what is
  published after its revocation.

#### What is still Tor's design, and what is not

| Tor | Vox |
|---|---|
| HSDir hash ring — third parties holding a blob they cannot read | the room's log. **Not members-only:** an anchor holds room logs with no membership, passphrase or sender keys (`node/anchor.rs`), so the first draft's "only members sync" was false |
| superencrypted layer, keyed off the blinded pubkey | **not reproduced.** The name lives *inside* the sealed body, so there is no party who holds the descriptor and knows the name without approval — except a revoked reader, who kept both |
| inner encrypted layer holding the introduction points | the content entry's body: nonce, ports, host identity, room, version |
| one `auth-client` wrapper per authorized client (`hs_descriptor.c:712`) | the author's sender key, which only consented readers hold |
| `descriptor-lifetime 180` (`hs_descriptor.c:14`) | not reproduced — Tor's descriptors live on strangers' disks with no revocation channel, and Vox has one |

**One layer, and the honest reason.** The first draft justified it with "there is no party who holds the
descriptor, lacks approval, and knows the name", and review demolished that: every revoked reader is such a
party, and a non-member anchor operator becomes one the moment a name is published anywhere. The correct
justification is different and does hold — **the enforcement is the dial-time consent check, and the name
being inside the seal is a second-order privacy benefit rather than a layer of access control.** Two layers
would add nothing, because a party excluded by the sealing is already excluded whether or not it knows the
name.

**What is still visible.** Recorded rather than glossed:

- **The audience size**, inherent to per-recipient sealing as ADR-006's SKDM already is. Tor pads its
  `auth-client` entries with fakes for this reason (`hs_service.c:1889`); Vox does not pad today, and
  whether to is left open as an ADR-006-level question rather than decided here, because it affects every
  entry and not only descriptors.
- **That the host published something**, and its size. Content entries are already like this.
- **Correlation across rooms.** A name is stable for a (host, room), so an approved reader in one room that
  recognises a name published elsewhere can correlate. And an approved party who publishes a name discloses
  the service's existence — no encryption scheme survives that. See the correction to decision 1's
  "without consequence" claim in Consequences.

#### Publication triggers

`chain_id` alone is **not** a sufficient version, which review established. The descriptor carries a
monotonic `version` per (service, room) and is republished on **every** change to what it says or who may
read it:

| Trigger | Why `chain_id` misses it |
|---|---|
| consent **revoked** | `chain_id` advances (`node/channel.rs`'s `revoke_consent`; `SenderChain::rotated`, `group/state.rs:269`) — this one it catches |
| consent **granted** | `issue_consent` records the *current* generation and does not rotate (`node/channel.rs`'s `issue_consent`), so a newly approved reader would never see the standing descriptor. **This would have broken decision 3's "immediately"** |
| a port added or removed | no consent change at all |
| the local endpoint replaced (`--at`) | ditto |
| the service withdrawn | ditto — and a retraction must be published, not merely omitted |
| scheduled sender rotation | advances `chain_id` with no audience change (`node/actor.rs:2887`), and fires on send, so a quiet host would not republish |

So: **republish on any of these, ordered by `version`, and a client accepts only the highest version it can
open.** `chain_id` remains the revocation signal — ADR-007 specifies that revoking outbound consent advances
*"`A`'s own `chain_id`* … **not** the channel `epoch`"*, which review verified against the code — but it is
not the descriptor's version counter.

*Recorded because the decision was taken on a wrong premise and corrected before any code:* the decider
chose "tie it to the room epoch" from options that asserted revocation triggers an epoch bump. It does not.
A channel epoch advances only on a passphrase rotation (decision 11), a far rarer and heavier event, and
hanging descriptor freshness on it would leave a revoked reader's descriptor valid until someone rotated the
room's passphrase. Decision 10's third point said "on the epoch bump" and was wrong for the same reason; it
is corrected there.

**Finding #5 is downgraded to unverified.** The first draft treated "a new epoch clears every exclusion" as
established and made it a blocking prerequisite. Review showed the ADR comment cited was not proof and that
exclusion resolution accumulates qualifying historical exclusions without filtering on the head epoch
(`governance/evaluator.rs:519`, `:797`). Since `0x0013` is withdrawn entirely, the question is moot for
services; it remains an open question about the evaluator and is M17.8, which now blocks nothing.

The rejected alternative remains rejected, with a second reason: a room-wide plaintext announcement tells
members who cannot reach a service that it exists, and under decision 1 it would leak the *name*, which is
the one string the unapproved must not have.

Discovery is **convenience, never authorization**. Holding a descriptor never grants reach; the consent check
in `tunnel::session::accept` remains the only gate.

### 10. Withdrawing trust is immediate, and says so

Un-approving a reader:

1. **tears down that reader's live connections at once** — an `ssh` session dies mid-keystroke;
2. **tells the other end why**: the client reports *access withdrawn by \<host\>*, rather than closing as
   though the network had dropped;
3. republishes the descriptor at a new `version`, without that reader (decision 9's triggers — **not** "on
   the epoch bump", which the first draft said here and which contradicted decision 9's own correction);
4. refuses every subsequent dial at the consent check, independently of 3 — a reader who cached a descriptor
   it could once open must not be reachable on the strength of that cache;
5. **fails pending requests**, which is the part the first draft missed.

Point 5 was a real hole review found, and it is now **closed** (M17.11, below). The actor captured its
authorization snapshot when the tunnel *stream* opened — before reading the request — and took a *copy* of
the reacher set, so an approved attacker could open a stream, withhold its request, wait for the withdrawal,
and complete against the stale copy. No timing skill: patience was the whole attack.

The fix is that the reacher set is a **live handle** rather than a copy — a `tokio::sync::watch` channel the
actor writes in place (`node::tunnel::Reachers`). The snapshot is still taken at stream-open, because only
the actor may read channel state and a tunnel outlives the actor's attention; but what it carries is a view
of the current set, not a photograph of a past one. The dial gate reads it *after* parsing the request, so
a parked stream is judged by the decision that holds when it finally speaks.

A watch rather than a lock because the serving tasks need two things and a watch gives both: the value now,
for the gate, and a wake-up on change, for point 1 — cutting a session that is **already carrying bytes**.
A lock would have served the first and forced polling for the second.

Points 1, 4 and 5 are the enforcement; 3 is hygiene. Point 2 is a deliberate choice to hand the revoked
party a clear signal rather than an ambiguous failure: a silent close indistinguishable from a network drop
was considered and rejected by the decider. It leaks the fact of revocation to someone who can infer it
anyway, and an ambiguous failure invites the revoked party to keep retrying, which is worse for both sides.

A host that withdraws approval and later restores it has restored service reach as well, in the same act.
There is no separate service state to remember, because there is no separate service authorization.

### 11. Lifecycle: departure, rotation, and the rooms that already exist

Review found this section missing entirely. Each item below is a rule the implementation needs and did not
have.

**A host that leaves, or is removed.** ADR-007 has no single-member eviction; the room's blunt instrument is
a passphrase rotation and rejoin. So while a host is a member its services are its own to offer, and when it
is no longer one:

- its descriptors stop being acceptable at the epoch its membership ended, which means **the descriptor
  carries the epoch it was published under** and a client refuses one from an epoch it no longer recognises;
- its bindings are local state and simply stop mattering, because nobody can open its descriptors;
- existing streams are torn down on the same path as decision 10, since the host's own consent set is gone.

**Leaving one room does not disturb a service bound to another.** Bindings are per (service, room); the
nonce, and therefore the name, is per (host, room) by decision 4.

**A passphrase rotation is a total wipe at the channel layer** (`node/channel.rs`'s passphrase rotation): every
certificate and every exclusion goes, and consent must be re-issued. For services that means, explicitly:
every audience empties, every descriptor becomes unopenable, and **every host must re-approve its readers and
republish**. No service survives a rotation silently, and none is silently re-granted either — which is the
property the withdrawn `0x0013` failed to have. `vox serve` reports this when it detects a rotation it has
not republished for.

**Rooms that already exist cannot simply lose a genesis field.** `GenesisBody::service_grant` participates in
the genesis signature **and** in the channelID hash (`governance/genesis.rs`'s `GenesisBody`), so deleting the field would
change the identity of every room created with one, or make their genesis unreadable. Review called this the
most dangerous omission in the first draft, and it is. The rule:

- the genesis field is **retained on the wire and in the decoder**, so every existing room still parses,
  verifies and keeps its channelID;
- it is **no longer consulted for authorization** — `build_evaluator` stops passing it, and a room carrying
  one is treated exactly like a room without;
- **creating** a genesis with the field is refused, so no new room acquires one;
- `0x0013` entries already on a log **decode and are ignored**, and the tag is never reused;
- a node that still honours the old model is a **mixed-version peer** serving its own services under its own
  rules. It cannot grant reach to anyone else's service, because every host enforces its own consent set
  locally — so the exposure is bounded to that node's own services, and the release notes must say that
  plainly rather than implying an upgrade closes the hole for everyone.

M17.13 covers this, and it is the one item that must ship in the same release as M17.7 rather than after it.
## Non-goals

- **No new authentication scheme for the service being carried.** Vox routes and authorizes *reach*; the
  service authenticates its own users exactly as it always did. `ssh` keeps its keys, HTTP keeps its cookies,
  Postgres keeps its passwords. ADR-013's SSH certificate authority is narrowed accordingly (see Links).
- **No implicit exposure.** See decision 2.
- **No authorization derived from membership, and none from joining.** See decision 3. Joining a room,
  holding its passphrase, paying its proof of work, being admitted as an author on any peer's board, or
  answering someone's join confers **no reach**.
- **No authority over who may host.** See decision 3. Binding a port of one's own machine is not the room's
  business, so there is no `bind:` capability and nothing issues one.
- **No room-wide plaintext service announcements.** See decision 9.
- **No service reachable by a non-member.** There is no anonymous access tier and no "public" service.
- **No name that is a capability.** See decisions 1 and 9. Vox deliberately does not reproduce Tor's property
  that holding an address is sufficient to connect.
- **No IP-level anonymity, and no relay-mandatory mode to buy it.** See decision 6.
- **No global namespace, and no name resolution off the machine.** A `.vox` name is a commitment to a host
  key and a nonce; it resolves only inside a client holding a descriptor it could open. There is no
  directory, no registration, no DNS suffix to own, nothing to squat and nothing to enumerate.
- **No privilege, anywhere, ever.** `vox up` is an unprivileged loopback proxy (decision 5).
- **No padding of per-recipient audiences, yet.** Audience size is visible; whether to pad is an ADR-006
  question because it affects every sealed entry, not a decision taken here (decision 9).

## Consequences

### Positive
- **One authorization surface, and one kind of act.** Reading and reaching are the same decision, and every
  such decision is an explicit human one. The class of bug behind findings #1 and #2 — a second surface
  drifting from the first — has nowhere to occur, and the class review found in the first draft — an
  *automatic* grant on a surface meant to be deliberate — is closed by construction.
- **Step six is gone without a new mechanism.** No credential, no genesis field, no log entry kind for
  authorization, and no additional human decision. The approval already existed.
- **The descriptor needs no new crypto.** Publishing it as content inherits the audience, the hiding and the
  freshness from machinery consent already governs (decision 9).
- Every service gets a real name, in any room — the coupling that left chat-room services unnameable
  (`node/resolver.rs:27-30`) is dissolved.
- A member the host has not approved cannot learn that a service exists, and cannot distinguish its
  descriptor from an ordinary message.
- **No new key material.** The name commits to the composite key that already exists, so nothing new can be
  lost or leaked, and the construction stays post-quantum.
- Nothing about the carried protocol changes, so any TCP service works on day one.
- The entry point needs no privilege of any kind (decision 5). The carried session has no IP addresses of its
  own (decision 6).

### Negative
- **Host and guest must already share a room.** Handing a service to someone you have no room with is two
  flows: make a room, then serve. This is the step Tor genuinely does not have, and the previous revision's
  one-command answer to it is what proved unsound.
- **A joiner is readable by nobody until it approves someone.** The cost of making every direction explicit.
  It is a change to what joining a chat room does, and it is the deliberate price of closing the
  auto-consent hole.
- **Reach cannot be narrowed below "the members of this room that are in my ring"**, and three `vox grant`
  capabilities go: time-bounded access, reach-without-read, and authority over who may host. Reach to a
  non-member was never among them (`node/actor.rs:2735`).
- **Only the host can cut a reader's reach.** A room admin has no lever over another member's services short
  of a passphrase rotation (decision 11). Intended, and stated.
- **A stable name is a correlation identifier.** The first draft claimed a name could be pasted into a bug
  report "without consequence". That is wrong and is corrected: leaking the string confers no *reach*, but it
  discloses that the service exists and lets anyone who has seen the name elsewhere correlate. The accurate
  claim is *not a bearer capability*, not *without consequence*.
- **Audience size is visible** even when its contents are not — inherent to per-recipient sealing.
- **Immediate teardown means the service layer watches consent**, and must reach pending requests as well as
  spliced streams (decision 10 point 5).
- **A rotation wipes every audience and descriptor** and requires re-approval and republication (decision 11).
- **Existing rooms keep a dead genesis field for ever.** The compatibility cost of never breaking a channelID
  (decision 11).
- A tool has to be told about the proxy once (`ProxyCommand`, `ALL_PROXY`). Same as a Tor user. A tool with
  no proxy support (`psql`) uses `vox forward` and a local port.

### Neutral
- "Tunnel" narrows to mean the mechanism; existing ADR-013 text stays correct under that reading.
- `vox serve` keeps its name while changing its meaning, because the verb is right and the shape was not.

## Implementation plan

Each item is one branch, red→green, with the ADR updated in the same change (house rule). **No item here is
built.** Three independent reviews returned REVISE on the first draft of this plan; what follows is the
revised one.

**M17.1–M17.5 as previously written are superseded in part.** Built and standing: the resolver's and proxy's
transport work (M17.3). Built and to be **removed**: the genesis service grant and `0x0013` (M17.1, but see
M17.13 — the field is retained on the wire), and `vox serve`'s room creation (M17.2). **Not built despite
an earlier claim that it was:** M17.4.

- **M17.1 — *superseded.*** The genesis service grant and `0x0013` are withdrawn from *authorization* by
  decision 3; their seven golden vectors go with them. The wire field and tag are retained for compatibility
  (M17.13) and the tag is never reused.
- **M17.2 — *partly superseded.*** `vox connect` stands. `vox serve` is reshaped by M17.7.
- **M17.3 — *stands, with two corrections.*** `node::up`'s SOCKS5 datapath is unaffected. `node::resolver`
  must resolve a **name to a descriptor** rather than a channelID to a genesis creator, and must span **every
  descriptor this client can open** rather than one room — so `vox up` takes no room argument
  (`vox-tui/src/cli.rs:332`, `node/actor.rs:2763`). **The M17.3 gate (`node_m17_up_gate`) asserts the
  vulnerability**: it supplies a member set and zero governance entries, then proves successful traffic
  (`tests/node_m17_up_gate.rs:118`). It must be rewritten, not extended.
  - **Rehearsed end to end, 2026-09-21.** Four real commands on one machine, two profiles and a
    headless anchor: `vox node` → `vox serve 22` → `vox connect <address>` → `vox up <room>` →
    `ssh user@<52-char>.vox`. The host's own `sshd` answered through the overlay — remote software
    version `OpenSSH_10.3`, a completed SSH transport handshake, and authentication failing only for
    want of a key. **Three defects the gates could not have caught**, all of them in the composition
    rather than the mechanism, are recorded here because they are the argument for rehearsing at all:
    1. **The generated passphrase did not match itself.** `vox serve` handed the node the hyphenated
       form while `vox connect` stripped the hyphens, so every join was refused with no indication
       why. The release gate could not see it: it drove the node API directly and used one passphrase
       value for both sides.
       The first fix was wrong and is worth recording. It canonicalized — strip hyphens — at "the
       node's boundary", making a hyphen never part of a room passphrase. That broke an existing test
       immediately, for the right reason: a joiner calling `NodeNet::start_join` directly bypasses that
       boundary, so a room created through the node and joined through the library derived two
       different secrets. A rule any direct caller can violate silently is worse than no rule.
       **The fix is symmetry, not canonicalization:** the hyphens are part of the secret, nothing
       strips them, and there is deliberately no function that could. What is printed is what both
       sides use, byte for byte. The cost — a listener who drops the dashes gets it wrong — is real and
       accepted: this string is copied beside a 277-character address, not retyped.
    2. **`vox node` printed an anchor spec nobody could dial.** A wildcard bind advertises `0.0.0.0`,
       which names every interface to the kernel and nothing to a peer; it was printed as something to
       paste into `--anchor`. Undialable addresses are now filtered out of that line.
    3. **`vox up` refused to start on a race.** It dialled the host *before* binding, so a node that
       had only just joined — and therefore had not yet read the board — could not find the host and
       the command failed intermittently. Retrying inside the actor would have made it worse, because
       the actor is what reads the board. The dial is now **per request**: the proxy binds at once and
       asks the node to reach the host when a connection arrives.
  - **Automated as a real-binary proof. *Done 2026-09-21* (M17.15).**
    `crates/vox-tui/tests/service_rehearsal_proof.rs` runs the same four commands as **real
    child processes** over three separate profiles: `vox node` (whose printed `--anchor` spec
    the proof parses and uses, so an undialable spec fails there), `vox serve <port>` (whose
    room id, `vox://` address and **generated passphrase** are taken from its stdout and used
    verbatim, so a passphrase that does not match itself fails there), `vox connect`, and
    `vox up`. A **real SOCKS5 client** in the proof then sends the `.vox` **name** — not an
    address, which is the `socks5h` behaviour the design requires — and real bytes through a
    real TCP echo service, which must come back byte-identical. Nothing reaches into
    `vox_core`: if a person could not do it from a shell, the proof does not do it.

    **It found a product defect on its first run, which is the argument for it.** The proxy
    refused the first two CONNECTs over about four seconds — `Reply::GeneralFailure`, because
    `vox up` binds before it can reach the host (deliberately) and the first request can
    arrive before this node has read the board. For a person that is `ssh` failing and then
    working if they try again. Fixed by `node::up::reach_host_with_patience`: one request now
    waits up to 20s for the host, polling every 250ms, *inside that request's own task*. That
    does not reinstate the problem the eager dial had — that one blocked **binding**, so a
    proxy which came up could refuse everything for ever; this blocks only the request that
    is waiting. The proof asserts **one CONNECT, first try, no retry loop**, and is
    mutation-checked: reverting the patience makes it fail with the user-visible symptom.

    Two further observations recorded rather than fixed: `vox up` requires the **room
    passphrase** even though the join is durable, because the room's store is sealed under it
    (ADR-010) — so a guest keeps the passphrase for as long as it wants the service, not
    merely to join once; and the host's own stdout is the only place client attribution can
    come from, since the service sees every Vox client as `127.0.0.1` (decision 6), which the
    proof asserts.

  - **Superseded by the above (was: being automated).** The rehearsal above was run by hand, which is
    why its findings are recorded as prose rather than as a gate that would catch a regression. It is
    becoming `crates/vox-tui/tests/service_rehearsal_proof.rs`: the same four commands as **real child
    processes**, asserting real bytes through a real TCP service. The decider's rule is that a test counts
    only if it drives the shipped binary — *"if we have cargo tests at all they have to be real or they're
    just noise"* — and this is the one that proves the service feature works. It lands **before** M17.7, so
    that changing the authorization cannot silently break the product.
- **M17.4 — anchors as configuration. *Done 2026-09-22.*** `<config_dir>/anchors`, written by
  `vox node`, read by every command, merged under `--anchor` rather than replaced. Machine-wide, because
  `config_dir` is not per-profile. Gate: `anchors_config_proof.rs` drives real binaries and a client in
  its own profile joins with no flag; mutation-checked.
- **M17.5 — *superseded by M17.10.*** `0x000F` advertisements become decision 9's content descriptor.

New work, in dependency order:

- **M17.6 — every consent grant is caused by a keyring entry. *Done 2026-09-21.*** The invariant from ADR-007, stated as
  executable work. Two halves, both required before anything else: `learn_members` / `admit_author` stop
  creating members from a peer's board record on a self-signed record alone; and `join` stops calling
  `release_key_to(responder)` (`node/actor.rs:1764`), which issued consent that no ring entry caused.
  Gate: a bundle record synced from a peer's board does not make its subject a member; a node that joins a
  room through a member has issued that member **no** consent, verified by the responder being unable to
  read the joiner's first message until the joiner trusts it.

  **What this gate does NOT prove, corrected after review.** An earlier version of this item claimed it
  asserted "no consent grant exists anywhere on the log without a corresponding ring entry on its issuer"
  — the ADR-007 invariant. It does not: the gate never calls `NodeCommand::Consent`, and that path writes
  a grant without touching the ring, so the invariant is **false in the tree and untested**. All three
  reviewers made it their first finding. It becomes true in M17.7, whose gate must exercise the approval
  path, and the claim is withdrawn here rather than left standing.

  **What landed**, `sec_no_consent_without_a_ring_entry.rs`:

  - A member bundle record carries a required `Admission` — `Creator` (the genesis names it, and the
    genesis hash *is* the channelID, so it is self-evident to anyone holding the room) or
    `Witnessed(JoinWitness)`. Two variants rather than an `Option`, so "the creator" and "malformed" never
    look alike on the wire. New struct tag `0x0014`; the admission is inside the record's **signed body**,
    so a witness cannot be lifted off one record and stapled to another key's.
  - The witness is minted in `responder_exchange`, beside the verification that justifies it, and returned
    on `JoinFrame::Accepted`. The joiner checks it binds its own key, this room and this epoch before
    keeping it, and persists it (`SEG_ADMISSION`) because it republishes it with every bundle record.
  - `ChannelState::admit_from_board` is now the only way a board key becomes an author. A witness counts
    only if **this node already admits its signer**, which roots every chain in the creator.
  - Admission runs to a **fixpoint**: a board returns records in arbitrary order, so a single pass drops
    a record whose witness was signed by a member appearing later in the same batch. Found by the M14 gate,
    not by inspection.
  - `MAX_ADMISSIONS_PER_SWEEP = 8` bounds it. **A witness does not make injection impossible** — a member
    can sign one for a key that never joined, since nothing forces a signature to correspond to a real
    exchange. It makes injection *attributable*; the quota is what stops one compromised member exhausting
    `MAX_AUTHORS` and denying admission to every legitimate member thereafter.
  - `join` no longer calls `release_key_to(responder)`.

  **One correction to this ADR's own reasoning, found by building it.** Decision 3 argued that removing the
  join's release "costs nothing functionally" because the pairwise session is built by `ensure_session` and
  the SKDM merely rides over it. That is wrong: a PQXDH responder starts with **no chains at all** —
  `Ratchet::init_responder` says *"with no chains yet — they are established when the first inbound message
  triggers a DH ratchet step"* — so the join's `InitialMessage` creates the session without giving the
  responder a sending chain, and until the joiner speaks *over* the session no member can answer it. The
  old comment was pointing at something real. What was wrong was meeting that need with a **sender key**,
  which made a consent decision nobody took. `PairwiseFrame::Open` meets it with a sealed message whose
  plaintext is empty: the responder ratchets and gains a sending chain, and learns no key and receives no
  grant.

  **Mutation-checked**, twice: restoring `release_key_to(responder)` fails the gate on the sender key
  reaching the responder, and removing the witness-signer check fails it on an unadmitted signer admitting
  somebody.

  **Six existing gates needed correcting, in two distinct failure modes, and every one of them was
  green.** This is the clearest measure of how load-bearing the removed behaviour had become, and it is
  recorded at length because the second mode is the dangerous one.

  *Mode 1 — the gate asserted the defect.* Rewritten rather than extended, on the M17.3 precedent:
  `node_m14_gate`, both gates in `node_m15_anchor_gate`, and `node_m18_revocation_gate` each waited for a
  sender key to arrive **before anyone consented**, which is the automatic release. Each now has the
  relevant parties grant explicitly, and the properties under test are unchanged — two nodes chat and an
  unconsented third reads nothing; two symmetric-NAT clients form a swarm through their own anchor;
  members never online together converge; revoking one member keeps the others whole.

  `node_m18_revocation_gate` is the instructive one. Its comment read *"Alice must hold both joiners' keys
  before she serves anything: an ADR-004 responder has no sending chain until it has received."* The
  premise is **true** — it is the same fact that broke `Consent` and forced `JoinFrame::Open`. The
  conclusion was the defect: what a responder needs is a *ratchet message*, not a *sender key*.

  *Mode 2 — the label had drifted from the assertion*, so the gate was green, passing, and testing
  something nobody intended. `node_m15_anchor_gate` asserted `entries >= 3` as "genesis, consent and the
  message", but the genesis is never a DAG entry (`entry_count()` is `dag.len()`), so the third was
  another node's *automatic* consent, synced in. Both gates in `node_m19_trust_gate` labelled a check
  "both members admitted" while asserting `entries > 0` — and the entry they waited for was that same
  auto-consent, so the check could never pass once it was gone, while the property they named had been
  true all along. Both now assert membership directly.

  `node_m14_gate` is also what caught the ordering bug above.
- **M17.7 — the trust keyring is the authorization. *Done 2026-09-22.***

  **The gate is not what this plan first said.** It was to key on `readers_of(host)`, the log's
  consent set. All three reviewers refused that, and codex gave the counterexample: that set records
  signed consent *edges* and checks neither current room membership nor current ring membership, so a
  grant from epoch 0 still appears after an authorized rotation to epoch 1. Keying on the **ring** —
  local, current, and the host's own decision — means the epoch question never reaches the gate:

  ```text
  reach(client, service) ⟺ client ∈ this host's trust keyring
                         ∧ client ∈ the bound room's current author set
  ```

  Computed by the actor, the only place holding both the node-wide ring and the channel's author
  table, and snapshotted per accept into `HostService::reachers` so the serving task never reaches
  back in. **This removes M17.8 as a prerequisite** — a simplification the review produced, not a
  corner cut. `service_tag` is no longer an authorization input at all: reach is per (host, room).

  **What makes finding #1 dead:** `Evaluator::service_grant_verdict` returns `None`
  unconditionally. The genesis service grant confers nothing, so joining is no longer
  authorization. The field and its bytes stay (M17.13) — it is inside the genesis signature and the
  channelID hash — and it decides nothing.

  **`add_service`'s `bind:` check is gone too**, which this plan called for and the first cut missed.
  Leaving it would have gated reach and offer by different models, only one of which moved: a plain
  member could be reachable and still unable to serve. Found by the agent-comms session hitting it
  from the file-exchange side.

  **New CLI, because the feature is unusable without it.** M17.7 makes trust the authorization, and
  there was no way to trust anybody from a command line — `vox trust` had been deferred to a later
  milestone that was itself waiting on M17.7. `vox id` prints this profile's 52-character
  fingerprint alone on a line; `vox trust add <fingerprint> --name <petname>`, `vox trust list` and
  `vox trust remove` are the decision surface. They are one-shot verbs that open the profile, so they
  cannot run while `vox serve` or `vox daemon` holds it (redb is single-writer) — trusting happens
  before serving, or through the control socket.

  **Proof** — `crates/vox-tui/tests/service_rehearsal_proof.rs`, real binaries throughout:
  `vox id` on the guest → `vox trust add` on the host → `vox serve` → `vox connect` → `vox up` →
  real bytes through a real SOCKS5 client. **And the control that makes it mean something:** a second
  guest holding *both* the address and the passphrase, whom the host never decided about, joins
  successfully and carries nothing. Under the withdrawn model those credentials were sufficient.

  **Stale output swept.** `vox serve` printed "anyone who joins with both may reach it" and
  `vox service add` printed "it is dark until you `vox grant` someone dial:" — both true of the
  withdrawn model, both the opposite of what the binary does. Neither was caught by three ADR
  reviews, because nobody re-read the `println!`s.

  **Measured, and not flattering:** the first connect after `vox up` has been observed at 7.7s and
  88s for identical code, because the wait covers a cold node connecting to an anchor, syncing a
  board and dialling through the ladder. `HOST_PATIENCE` is 300s for that reason — a bound
  calibrated on an idle machine expires under load and reinstates the very defect it fixed.

  *Superseded plan text follows.*

- **M17.7 — consent is the authorization.** `build_evaluator` stops passing `authors.keys()`
  (`node/channel.rs`'s `build_evaluator`); the dial check keys off **(in the host's trust keyring) AND (in the bound
  room)**. `vox grant`, `GenesisBody::service_grant`'s authorization role and the `bind:` class with
  `add_service`'s `can_bind` check (`node/channel.rs`'s `add_service`) are removed. `vox serve` takes a room,
  creates none, and names its audience and non-audience. The consent prompt states that approval confers
  service reach. Gate: an unapproved member is refused, an approved one reaches the service, the transition
  happens on the approval alone with no second command, and a member who is not the room's creator can
  serve — which fails today. **Plus the keyring cases, which are the gate's real shape** (decision 3, and
  the corrected reading: an earlier draft of this item had it backwards, requiring keyring-consented members
  to be *refused*): a member trusted only through `vox trust add` and never approved in the room **does**
  reach the service once it is in the room; a member of the room that is not in the ring does not, and
  cannot learn the service exists; a trusted identity that is **not** in the room reaches nothing bound to
  it; and a trusted identity that joins **after** the service was bound gains reach on joining, with no act
  by the host at that moment.
- **M17.8 — the evaluator's head-epoch filtering. DONE 2026-09-22 — the resurrection cannot happen.**
  The gate was "a test that either exhibits the resurrection or shows it cannot happen", and the answer is
  the second: `vector_m17_8_a_rotation_empties_the_audience_and_a_stale_epoch_grant_is_inert`.

  The concern was that `consent()` folds grants and revocations last-write-wins over the causal order with
  no *visible* epoch filter, so a grant landing after a rotation would win on position and resurrect a
  revoked reader. It does not, because `Evaluator::in_effect` gates every entry first: an entry counts only
  if its body epoch equals the epoch established in its **strict causal past**. An entry naming a retired
  epoch is inert, so replaying a pre-rotation grant — or a partitioned client catching up with one — buys
  nothing.

  Isolated rather than asserted once, because a reassuring property is exactly the kind that rots into a
  green test nobody re-reads:

  | log | `can_read` |
  |---|---|
  | rotate 0→1, then a grant stamped **epoch 0** | **false** — inert |
  | rotate 0→1, then a grant stamped **epoch 1** | true — a current grant still counts |
  | no rotation, then a grant stamped epoch 0 | true — epoch 0 is still current |

  The second leg is what keeps the first meaningful: without it the vector would also pass if the filter
  rejected every post-rotation grant, or if consent were broken outright. Mutation-checked by making
  `in_effect` return `true` unconditionally, which fails the first leg.

  **Two of three plan reviewers called this a prerequisite for M17.7**, on the grounds that without it a
  passphrase rotation would not empty the audience at the dial gate. It is neither a prerequisite nor a
  defect: the rotation does empty the audience, and since M17.7 the dial gate does not consult the
  evaluator at all — reach is the host's keyring intersected with the room's author set. What the fold
  governs is **readability**, which is ADR-007's older and separate promise, and it holds.
- **M17.9 — the name.** `H("vox service name v1" ‖ host_composite_pk ‖ nonce)` in base32; nonce minted per
  (host, room) on first serve, reused for further ports, retired with the last one; persisted in the profile.
  `node::resolver` resolves name → descriptor across rooms. Gate: a name survives a restart, two ports share
  one name, a second room yields a different name, a retired-then-reserved service gets a *new* name, and a
  name for a service this client holds no openable descriptor for does not resolve at all.
- **M17.10 — the descriptor.** A content entry per (service, room) carrying nonce, ports, host identity, room
  and a monotonic `version`, republished on every trigger in decision 9. Gate: an approved reader lists the
  service by name without being told it; a **newly** approved reader does too, without waiting for anything
  (the trigger `chain_id` misses); an unapproved member of the same room cannot determine the name, the
  ports, or that the entry is a descriptor rather than a message; a reader whose consent is withdrawn cannot
  open the next version; and a retraction is published rather than the entry merely ceasing.
- **M17.11 — immediate teardown, including pending requests. DONE** (2026-09-22), and it ships with M17.7
  because a parked stream defeats a withdrawal with no timing skill at all.
  - The reacher set is a live `tokio::sync::watch` the actor writes in place (`node::tunnel::Reachers`),
    refreshed by `NodeActor::refresh_reachers` whenever either input moves — the keyring (`Trust`,
    `Untrust`) or a room's author set (any board admission) — and once per accept as a backstop. The write
    is `send_replace`, which both updates the value the gate reads and wakes every serving task.
  - **A pending request** is judged after it is parsed, from that live set
    (`tunnel::session::accept_reporting`), so a stream parked across the withdrawal is refused.
  - **A live session** is cut: `splice_until_withdrawn` selects between the byte copy and the watch, and
    leaves the moment the client is no longer in the set. The QUIC stream is **reset** with
    `REACH_WITHDRAWN_CODE` (`0x1711`), not finished, because a clean close is indistinguishable from the
    carried service hanging up.
  - **The reason reaches the far end.** The dialer maps that reset code to `Error::TunnelRevoked`; the proxy
    reports it through `up::serve_reporting`; the node turns it into `NodeEvent::ReachWithdrawn`; and
    `vox up` prints that the host withdrew access and that there is nothing to retry. A *refused dial* still
    says nothing (dark services), and that asymmetry is deliberate: a peer whose established session is cut
    already knows it had reach, so naming the reason leaks nothing and saves it retrying against a decision
    that will not change.
  - Proof: `crates/vox-core/tests/m17_11_parked_stream_proof.rs`, two tests over real QUIC with a real TCP
    service. The first opens a real tunnel stream, waits until the host has served it, withdraws reach, and
    *then* sends the request — asserting both that it is refused **and that the service was never dialled**.
    The second proves a round trip through the service, withdraws reach mid-flight, and asserts the dialer
    gets `TunnelRevoked` rather than a generic failure. The client is hostile by construction (it writes the
    request frame itself so it can choose when), which is the only way to produce a parked stream: no honest
    client ever delays.
  - Each half has its own mutation: snapshot the set again and the parked request is accepted and the echo
    logs a hit; drop the `changed()` arm and the live session flows on; `finish()` instead of `reset()` and
    the dialer cannot tell a withdrawal from a normal close.
  - **Corrected 2026-09-22 — the first cut of this tore down live sessions it had no business
    touching.** `refresh_reachers` wrote the sets with `watch::Sender::send_replace`, which notifies
    unconditionally, and it runs on **every accept**. So every new tunnel stream woke every serving task in
    every room, and a serving task answers a wake by re-evaluating whether to cut the live session it is
    carrying. That reached a person as `Connection reset by peer` mid-transfer with nobody having withdrawn
    anything — reproduced on `edfdcc5` by the agent-comms session while reading an echo back, after I had
    reported the mechanism as a hypothesis I could not reproduce myself.

    **A recompute is not a decision.** There is now exactly one writer,
    `node::tunnel::publish_reachers`, which notifies only on a real change, and a locked node no longer
    recomputes at all — `lock` clears the keyring because it is sealed under the identity, so recomputing
    there produced an empty set that read as "everyone was withdrawn" and would have cut every live tunnel
    on a SIGHUP (ADR-015). Splicing needs no identity; locking is about what this node can *read*.

    Proved by `m17_11_an_unchanged_recompute_does_not_wake_the_serving_tasks`. The discriminating
    observable is **the wake, not the survival** — under the old code a spurious wake happens and the task
    usually re-checks membership successfully, so a test that merely kept a session alive across recomputes
    would have passed on the broken code. A first draft did exactly that and was deleted. Mutation: put
    `send_replace` back inside `publish_reachers` and it fails.

    **Not yet confirmed:** whether this fully accounts for the mid-stream reset observed in
    `service_rehearsal_proof`. The spurious wake is removed and cannot recur, but if a reacher set moves
    *genuinely* for a moment — an author set rebuilt during sync, say — the teardown would still fire and
    this does not touch it. The open cross-process join defect (ADR-016) fails the same gate first, so runs
    cannot currently distinguish them. If it recurs, the fix is to make a withdrawal an explicit act the
    actor announces rather than something a serving task infers from set membership.
  - **Not covered:** a *room-level* `Revoke` of a **trusted** identity, because M17.14 makes that refuse
    outright (`Fault::StillTrusted`) — "revoked here but still trusted" is not a state the model has, so
    there is no path by which it could remove a reacher. `Untrust` is the act that means it.
- **M17.12 — the validation contract.** The descriptor binds name, host, room, ports and version; the client
  authenticates the transport peer as that named host before carrying a byte; the resolver holds
  `name → (channel, host, port)` and the tunnel request carries the port as its tag. Gate: a descriptor
  copied verbatim into another room does not resolve there; two hosts serving `:22` in one room are reached
  by their own names and never each other's; and a rebound port does not answer on a stale name.
- **M17.13 — compatibility. DONE 2026-09-22**, and it shipped with M17.7. The genesis field and `0x0013`
  keep parsing so every existing room keeps its channelID (`governance/genesis.rs`'s `GenesisBody`), and
  neither is consulted for authorization — `Evaluator::is_excluded` remains as the parsed fact with no
  authorization path reading it.
  - Proof: `crates/vox-core/tests/m17_13_v010_compat_proof.rs`. The fixture beside it was produced by
    **building the `v0.1.0` tag (875e2f8)** and printing what that binary computed for a genesis with fixed
    seeds, a fixed nonce and a non-empty service grant. The comparison is therefore against a real old
    build; today's code agreeing with itself would prove nothing about compatibility.
  - It asserts three things: today's encoder produces v0.1.0's canonical body **byte for byte**; the
    channelID is unchanged (`c82a371c…`), so the room keeps its name and its `.vox` hostname; and that
    grant authorizes **nobody** — `dial:22` and `dial:ssh` are both refused to a full member of that room.
  - Bodies are compared whole rather than field by field, deliberately: a mismatched `e.array(N)` fails
    *silently* — a record is simply rejected three layers from the cause — which has already happened once
    in this codebase.
  - Mutation-checked both halves: `e.array(6)` → `array(7)` fails the byte comparison; restoring
    `service_grant_verdict` fails the authorization assertion, naming finding #1.
  - **Still to write:** the release note that a mixed-version peer applies the old rules **to its own
    services**. That is bounded — every host enforces its own reach locally — but it is a real caveat for
    anyone running v0.1.0 and this build in the same room, and it is not yet written down anywhere a user
    would see it.

- **M17.14 — withdrawing trust changes the lock. *Done 2026-09-21* (`5fefcbb`).** `NodeCommand::Untrust`
  removes the ring entry and then walks every channel where consent was actually granted, reusing M18.1's
  revocation rather than adding a second kind. The gate stands up **two** rooms shared with the removed
  party and asserts the property in both — a single-room gate passes against an implementation that only
  ever changes the lock in whichever room comes first. Original statement of the work follows. `Untrust` is forward-looking only as built in M19.2
  (its own docs: *"recalls nothing already granted; recalling that is Revoke, per room"*), so a withdrawn
  identity keeps reading the withdrawer's **new** messages in every shared room. Removal must instead
  perform ADR-007's revocation — rotate the sender key, record the fact, re-key everyone still in the ring —
  in every room shared with the removed identity, best-effort with the tick retrying whoever is offline.
  Gate: a key trusted, used to read, then removed **cannot read a message published after the removal**, in
  every shared room, while a third identity that stays trusted reads it throughout. Independent of the
  service work; service reach is already cut at the dial gate.

M17.6 must land first and alone: it closes both the admission hole and the auto-consent hole, and M17.7's
gate is meaningless until it has. M17.7 and M17.13 ship together. M17.9 blocks M17.10 and M17.12. M17.11
depended on M17.7 and shipped with it. M17.8 is independent of all of it.

## Open proof gap: the residual 30-second serialisation is unproven

> **CLOSED 2026-09-24 (v0.2.8).** `spawn_accept_loop` now spawns each handshake on its own task,
> bounded at `HANDSHAKES_IN_FLIGHT` (64); at the cap an unvalidated attempt gets a QUIC `retry()` and
> a validated one `refuse()`, never a queue. The revert recorded below was taken on evidence that
> belonged to a different defect: the 247s `m15_two_clients…` timeout was sync starvation (a room's
> in-flight mark let a failing anchor session take the room every round), which also hit the serial
> loop in 9 of ~15 CI runs on `main`. With that fixed, the split exposed the one real dependency on
> the serial order — and it was not in the accept loop but in `ConnectionManager`'s duplicate
> tie-break, "the held connection wins", which two ends agree on only if they file a pair in the same
> order. It is now an order-independent TLS-exporter key (`tie_key`). Measured with both ends logging
> each connection's exporter tag: 2 of 5 duplicate pairs disagreed before, 0 of 28 after.
>
> Acceptance, real binaries and the release proofs: `order4.sh` (a host and two back-to-back
> joiners) J2 in 5/5, against 0/5 on pristine `main`; `service_rehearsal_proof` 3/3, back in the
> blocking gate; `node_m15_anchor_gate` whole binary 6/6 runs (18/18 tests); `node_m14_gate` 3/3.
> The text below is kept as the record of how it was reached.

**M17.17 (verified finding #3) is PARTLY fixed and the remainder is NOT proved.** Recorded here rather than left
implied, because ADR-018 §4 is explicit that absent evidence must not read as success — and because a
green test that does not discriminate is worse than no test.

**The defect.** `spawn_accept_loop` called `NodeNet::accept`, which awaits the TLS handshake inline, so
the loop could not take the next attempt until the current one finished. One peer that opened a
connection and then stopped talking blocked **every** other inbound connection, with no credential of
any kind — authentication happens inside the handshake, so at the moment of the stall there is nothing
to hold the peer to. Worst against an always-on, publicly addressable node, which is what an anchor is.
The loop's own comment claimed a slow peer could not stall the others; that was true of the *stream*
loop, which runs after the handshake, and is why the defect survived review.

**What actually shipped, corrected 2026-09-22.** The two-phase API exists — `accept_incoming` takes the
attempt and returns, `finish_incoming` completes the handshake and admission bounded by a 30s
`HANDSHAKE_TIMEOUT` — but **`spawn_accept_loop` does NOT spawn phase two.** It still calls
`ConnectionManager::accept`, inline.

That is a smaller fix than the one described above, and it is not nothing: `accept_with_admission` routes
through `finish_incoming`, so the inline path inherits the 30s bound. **The unbounded case is gone.** A
peer that opens a connection and never finishes its handshake now delays other inbound connections by at
most 30 seconds rather than for ever. What remains is a 30-second serialisation window, which is a real
residual DoS against an anchor and is stated as one.

**The residual is no longer unproven (2026-09-23).** This section's title says the 30-second
serialisation is unproven, and that was the honest state: the cost was reasoned from the code and the
only thing that failed because of it was an intermittent proof nobody could attribute. It now has a
deterministic, two-process, real-binary reproduction — one host and two sequential `vox connect`s, no
trust, no malice, nothing exotic:

| what | result |
|---|---|
| a **lone** joiner 35s after the host starts | in, 2s |
| a second joiner **immediately** after the first | **locked out** — `direct attempt timed out` against the host's real, still-bound port |
| a second joiner **40s** after the first | in |

The host prints `vox: <first joiner> joined` and then says *nothing at all* about the second, because
the second's handshake never reaches it. The socket stays bound, so the symptom is a timeout rather
than a refusal, and it surfaces three nodes away as `Fault::Unreachable` against a peer that is up and
listening. The recovery at 40s is what identifies the window as `HANDSHAKE_TIMEOUT` rather than
anything permanent.

**A joiner's `vox connect` is a one-shot: it exits the moment it has joined.** So the ordinary,
intended use of the product leaves the host mid-handshake on something and deaf for the next 30
seconds — no attacker required. That is what makes this a defect rather than a hardening item, and it
is the cause of `service_rehearsal_proof:490`, which has been read as a flaky proof and has blocked
releases (ADR-018).

It also matters for what "proved" has to mean here. Those two NAT gates are the acceptance test for
*splitting* the handshake; the reproduction above is the acceptance test for *not* splitting it. A
change to this loop must now satisfy both, and until this session only one of the two existed — which
is why the serialised version could be shipped as the safe option. It is not the safe option; it is
the option whose cost had no test.

**Why the loop is not split, measured.** Spawning phase two per attempt makes circuit establishment
between peers behind symmetric NATs wildly variable. Same gate, same box, same commit:

| accept loop | `m15_two_clients_behind_symmetric_nats…` |
|---|---|
| serialised (shipped) | 40–52s, consistently green |
| split | 68s, 140s, and a **timeout at 247s** |

Two hypotheses were tested and **refuted**: the one-connection-per-peer rule in
`ConnectionManager::file` is not implicated (instrumented — it never closed a loser or retired an
existing one across a whole passing run), and per-connection ordering is identical in both versions
(file → `spawn_stream_loop` → `Connected` in each). So the cause is a cross-connection interaction in
circuit establishment that is **not yet identified**, and no theory should be recorded here until it is.

Worth noting that the split is quinn's own documented shape — its `examples/server.rs` does
`while let Some(conn) = endpoint.accept().await { … tokio::spawn(handle_connection(conn)) }`, awaiting the
handshake inside the task. So the shape is not the error; an assumption of ours that the shape violates
is. Those two NAT gates are the acceptance test for whoever finds it.

**Why it is unproven.** A test was written and **deleted**, because its mutation check did not
discriminate: with the old serialised loop restored it still passed. The reason is instructive — the
synthetic "stalling peer" was a raw UDP socket sending one long-header datagram, which quinn discards
without ever creating an `Incoming`. Nothing was pending, so nothing was blocked, and the test was
measuring an empty accept loop. A real loopback handshake completes in about 1.6ms, so a serialised loop
handling eight *valid* peers is also fast enough to pass any budget — the property only bites when a
handshake is genuinely slow, and synthesising that needs a peer that sends a **valid** QUIC Initial and
then stops, which this suite cannot currently construct.

**What would close it**, in order of preference: a cooperating slow client built on a raw quinn endpoint
that completes the Initial and then stops polling; or a two-machine rehearsal where one side is
suspended mid-handshake (`SIGSTOP` on a real `vox` process after its first datagram), which is the
`service_rehearsal_proof` style and the more likely to be honest.

Until then the fix rests on the shape of the code and on the defect being legible in the diff, which is
weaker evidence than this repository's bar, and is stated as such.

## Links
**Depends on**: ADR-005 (the invite and its passphrase separation), ADR-006 (the sender-key sealing the
descriptor rides as content), ADR-007 (per-sender consent — now the authorization basis — and revocation),
ADR-012 (reachability, anchors), ADR-013 (the tunnel data path), ADR-016 (the node that runs it).
- **Restores an ADR-013 invariant this ADR had qualified.** ADR-013 holds that *"tunnel capabilities are
  never inherited from membership."* The previous revision carved out an exception for a room's immutable
  genesis; decision 3 **withdraws the carve-out**, so the invariant stands unqualified again.
- **Reverses ADR-013's orthogonality claim.** It held that revoking message consent does not touch tunnel
  access and vice versa. They are now one axis.
- **Removes ADR-007's `bind:`/`dial:` capability pair from the service path** and `0x0013` with it, while
  keeping both decodable for compatibility (decision 11).
- Amends ADR-013 further: the SSH CA is narrowed to an optional later capability; `vox forward` remains the
  path for tools with no proxy support, under the same consent check; the SOCKS5 front-end is the
  person-facing entry point and must become room-agnostic (M17.3).
- Leaves ADR-014 as it was: its privileged helper / `NetworkExtension` stays **conditional on a TUN
  interface that is not on this path**.
- Depended on by: ADR-014, ADR-015 (the clients surface these verbs).
- **Reviews on file**: `docs/adr/ADR-017-reviews/` — three independent REVISE verdicts on the first draft of
  this revision, and the evidence for every correction recorded above.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
