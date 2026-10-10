# ADR-030: Post-Quantum Post-Compromise Security for Pairwise Key Delivery

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.2 (the decider, 2026-10-09; first accepted for v0.5.0, moved to v0.4.2 the
same day). Nothing in this ADR is built.
**Date**: 2026-10-09
**Deciders**: Robert E. Lee
**Tags**: crypto, post-quantum, pairwise, sender-keys, prekeys
**Related**: ADR-001, ADR-002, ADR-003, ADR-004, ADR-006, ADR-018
**Inputs**: the decider's product Q&A of 2026-10-09; Signal's ML-KEM Braid and Double Ratchet
(revision 4) specifications; Apple's PQ3 design and its analyses (Stebila, ePrint 2024/357; Linker,
Sasse and Basin, ePrint 2024/1395); Dodis et al., ePrint 2025/078; Auerbach et al., ePrint 2025/2267;
Alwen, Coretti and Dodis, ePrint 2018/1037; Schmieg, ePrint 2024/523.

## Context

ADR-004 provides forward secrecy, classical post-compromise security, and PQ confidentiality against
a passive quantum adversary: PQXDH mixes an ML-KEM-768 secret into the session's first key, and every
later key descends from it. ADR-004 Q1 left PQ post-compromise security (PQ PCS) unbuilt. An
adversary who steals a member's state once and holds a quantum computer can recover every later
X25519 ratchet secret from the public keys on the wire. That adversary reads the session from then
on, and every sender key carried in it, so it reads the rooms too.

Deployed PQ ratchets heal through conversation traffic. Signal's SPQR spreads an ML-KEM exchange over
dozens of messages in both directions; Apple's PQ3 re-keys about every 50 messages. Vox's pairwise
session carries almost nothing but sender-key distribution messages (SKDMs), roughly one per rotation
per peer, mostly one way; `KEY_TAKEN` is a stream byte, not a ratchet message (ADR-006 S-17). A
ratchet that heals only when both sides send heals on this traffic in weeks or never. Signal's
specification says a session where one party stops replying "will never heal".

PQXDH needs no round trip: the recipient's published prekey supplies the fresh encapsulation key.
ADR-006 S-6 already makes sender-key rotation the room's only recovery event. This ADR therefore
binds PQ freshness to every key delivery, not to the ratchet.

## Requirements

### 1. Key delivery

- **D-1. Every key delivery travels in a fresh session.** A sender key, or any other key a node hands
  to a peer over the pairwise channel, MUST be sealed in a session the sender opens with
  `Session::initiate` after deciding to send that key, against the recipient's current bundle. It
  MUST NOT be sealed in the long-lived session (ADR-004 O1–O4) or in any session that existed before
  the decision.
- **D-2. The sender is always the initiator.** A key delivery session MUST be initiated by the node
  that sends the key. A responder-side compromise heals only when the responder's prekeys roll (§3),
  so the sending side MUST never become the responder through the ADR-004 O2 race.
- **D-3. Every delivery path.** D-1 MUST hold on every path that seals a key: rotation and re-key
  delivery (`deliver_rekeys_for`), release to a member (`release_key_to`: retrust, consent grants,
  history releases), and key packages (`post_key_package`, already one-shot).
- **D-4. One session per (recipient, key).** A sender MUST open one delivery session per recipient
  per key. It MUST keep that session's hello bytes and state until the recipient answers `KEY_TAKEN`
  or a later key supersedes it, and a re-carry (ADR-006 S-17) MUST resend those exact bytes, so a
  flapping stream burns no further one-time prekeys.
- **D-5. No fallback.** If no acceptable bundle is available (§3), the key MUST wait. It MUST NOT be
  sealed in an older session. The node MUST say why the key is waiting, with a reason distinct from
  "no bundle" and "no session could be opened", and what that costs.
- **D-6. Any future payload.** A new kind of confidential payload on the pairwise channel, such as
  v0.5.0 call keys, MUST follow D-1 until this ADR is reopened for that payload.

### 2. Wire and receiver

- **W-1. A distinct frame.** A key delivery session MUST travel as its own pairwise frame,
  `OP_ROTATION_HELLO`, carrying the PQXDH initial message and the sealed key together. It MUST NOT
  reuse `OP_HELLO`, which keeps its ADR-004 O2 meaning (a lost session to replace).
- **W-2. Never the long-lived session.** A receiver MUST open the key under the transient session
  built from that frame, then drop the session. It MUST NOT insert the session into, replace, or
  consult the long-lived session table. It MUST NOT apply ADR-004 O2–O4 to it.
- **W-3. Its own dedup.** A receiver MUST dedup delivery frames in a slot of their own, never in the
  long-lived session's accepted-hello record, so a delivery cannot evict that record's replay pin.
  A replayed delivery frame whose key was already taken MUST be answered `KEY_TAKEN` without opening
  anything; ADR-006 S-12 makes a duplicate SKDM inert.
- **W-4. Lockstep.** A node that predates this ADR refuses `OP_ROTATION_HELLO` as an unknown frame
  and resets the stream. That refusal MUST be the whole mixed-version behaviour: the key waits (D-5),
  and no state is damaged or downgraded. There is no capability bit and no classical mode to fall
  back to.

### 3. Prekeys

- **P-1. Retire unused one-time prekeys.** A node MUST retire every one-time prekey not consumed
  within one signed-prekey cadence (ADR-002 R2.2, 7 days). It MUST keep a retired prekey's secret,
  unadvertised, for a grace of 1 hour, so a delivery already in flight still opens.
- **P-2. Refuse a stale bundle.** A sender MUST refuse a bundle whose signed prekey's root-signed
  creation time is older than one cadence. It MUST NOT judge staleness by the record's own
  publication fields. The check MUST sit in the sender's fetch path. A sender MUST also refuse a
  bundle whose signed or one-time prekey's root-signed creation time is more than 10 minutes ahead
  of its own clock, and say so in plain words (D-5), so a recipient clock running fast extends the
  cadence bound by at most 10 minutes (the decider, 2026-10-10).
- **P-3. Refused one-time prekeys.** When a recipient answers that it does not know the one-time
  prekey a delivery named, the sender MUST fetch the bundle again and MUST NOT target that prekey id
  again. Nor MUST it name a one-time prekey that an earlier delivery named. When the bundle it holds
  names such a prekey, the key MUST wait for the recipient's next bundle (D-5). A node MUST
  republish its bundle as soon as the prekeys it offers change. If no bundle naming a fresh
  one-time prekey arrives within 30 seconds while the recipient is connected, the sender MAY
  deliver to the signed prekey, and MUST say so once (the decider, 2026-10-10).

### 4. What this provides

- **S-1. A compromised sender heals at once.** If the sender's whole state was stolen and the
  adversary is now passive, the next key it delivers is safe, with no round trip. The delivery
  session's secret rests on a fresh ML-KEM encapsulation to a key the adversary does not hold.
- **S-2. A compromised recipient heals within the cadence.** If the recipient's state was stolen, a
  delivery is safe once it targets a one-time prekey minted after the compromise, or a signed prekey
  rotated after it. P-1 and P-2 bound that to one cadence plus the previous signed prekey's retention
  (ADR-002 R2.2). Bundles republish about hourly, so a waiting key (D-5) waits about an hour plus
  propagation, not a cadence.
- **S-3. Rooms.** Group recovery is as post-quantum as the session that carries the rotated key
  (ADR-006 S-6). Under D-1, every rotation is post-quantum fresh.
- **S-4. Out of scope.** This ADR provides nothing against an active adversary holding a stolen
  identity key, or an active quantum adversary during the handshake (ADR-004 S1).
- **S-5. Stated degradations.** These MUST be stated wherever S-1 to S-3 are claimed:
  - A delivery whose recipient published no fresh one-time prekey within 30 seconds of the last one
    being named (its pool exhausted, or its next bundle not arriving while it is connected) targets
    its signed prekey, which heals only on rotation.
  - Restoring a profile restores its prekey ring. P-1 bounds the resurrected one-time prekeys to one
    cadence.
  - A replay of a last-resort delivery inside the signed prekey's retention re-derives the same
    session. ADR-006 S-12 makes its key inert.
- **S-6. Precondition.** S-1 to S-3 hold only while D-1 covers every confidential payload on the
  pairwise channel. A change that adds a payload MUST state how it meets D-1, or reopen this ADR.

### 5. Proof

- **T-1. Blocking proof.** `revocation_rotates_the_key_proof` MUST be extended, with no new file
  (ADR-018). A test-side client holding a real member's profile is the attacker apparatus; it freezes
  its pairwise state before the shipped victim rotates. The proof MUST assert:
  - (a) the rotated key arrives in an `OP_ROTATION_HELLO`;
  - (b) the frozen state cannot open it;
  - (c) the fresh session does open it (positive control);
  - (d) a bundle the apparatus serves with a backdated one-time prekey is refused, with D-5's reason;
  - (e) a retrust delivers through an `OP_ROTATION_HELLO`.
- **T-2. Mutants.** Each MUST turn the proof red on its own assertion:
  - sealing the rotated key in the existing session turns (a) and (b) red;
  - skipping P-1 and P-2 turns (d) red;
  - routing `release_key_to` through the long-lived session turns (e) red.
- **T-3. Reds.** Every red MUST name PRODUCT, quoting the binary's behaviour (for example, "the
  rotated key the victim sent opened under pre-rotation state"), or APPARATUS (no rotation observed,
  no bundle served).
- **T-4. What the proof shows.** The proof shows the structural invariant that a delivered key never
  opens under pre-delivery state. That the PQ secret is absent from that state rests on the analysis
  in §4 and a symbolic model spike, run and reported, never committed (ADR-018).

## Alternatives rejected

- **SPQR (ML-KEM Braid).** On Vox's traffic one epoch, dozens of chunk-messages in the right
  directions, would take months or never complete. The `spqr` crate is AGPL-3.0-only, so Vox would
  have to reimplement it from the public-domain specification, with its erasure coder, state machine
  and proofs.
- **An unchunked ML-KEM step in the Double Ratchet (PQ3-shaped).** A compromised sender heals only
  after it receives a reply, and an attacker holding its chain key reads every SKDM it sends before
  then. It adds up to about 2.3 KB per ratchet step, a header and suite change, and a new hybrid
  composition to prove. Encapsulating on every send instead is a per-SKDM KEM, which this ADR would
  then have to justify over D-1.

## Consequences

- A compromised sender heals with its next key delivery, and a room with its next rotation, against a
  quantum adversary, with no new cryptographic composition: the shipped hybrid PQXDH is the whole
  primitive.
- Each key delivery costs one PQXDH initial message (about 1.2 KB) and, usually, one of the
  recipient's one-time prekeys.
- `pairwise/ratchet.rs`, `header.rs`, `session.rs`, `init_message.rs` and `suite.rs` are unchanged.
  The work is in the node's delivery paths, the pairwise frames and the prekey ring.
- v0.4.2 does not interoperate with v0.4.1 or earlier on key delivery (W-4).
- Recipient-side healing is bounded by prekey hygiene. Today nothing retires an unused one-time
  prekey, so that bound does not exist until P-1 lands.

## Related ADRs

Depends on ADR-002, ADR-003, ADR-004, ADR-006. Amends ADR-004 Q1 and O1–O4, ADR-006 S-4 and S-14.
Cited: ADR-001, ADR-018.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
