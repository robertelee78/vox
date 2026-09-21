I’ll read the three ADRs in the requested order, then trace the authorization, consent, discovery, and tunnel paths against the Rust and Tor code. I’ll distinguish design defects from current implementation gaps and cite the evidence for each finding.


---

ADR-017 explicitly marks the new authorization and descriptor work as proposed. ADR-013 and ADR-007 mix that proposal with claims about implemented behavior, including a claim that a gate was already rewritten; I’m checking those claims directly. The requested `governance/channel.rs` does not exist here—the channel runtime is `node/channel.rs`.


---

One material issue is already visible: the code creates an outbound consent grant automatically when a node joins a room, in favor of the join responder. That contradicts the plan’s premise that every entry in the host’s reader set records deliberate human approval. I’m tracing responder selection and checking whether that automatic grant would become service access under the proposed gate.


---

The `chain_id` correction is supported by the code: consent revocation rotates the host’s sender chain and records the resulting generation. But it is not a complete descriptor version: approval and service changes can happen without advancing it. I also confirmed that a non-member anchor stores the room’s log, so Decision 9’s “only members sync” premise is false; that alone does not prove a second encryption layer is needed.


---

The main admission flaw does stop at a correctly implemented host-consent check: a peer cannot forge the host’s signed consent merely by supplying board records. The automatic join grant is the exception the plan misses. I also found two concrete gaps to resolve before implementation: the surviving Bind check conflicts with deleting `vox grant`, and deleting a field from shipped, signed genesis records needs a compatibility plan.


---

For a separate follow-up after this review, MetaHarness can assess harness cost and routing (“score my harness”, “evolve my harness”, “do this cheaper”), and Agentic-QE can review tests and coverage (“QE this”, “check coverage”). Would you like an explainer or a run?
- No extra work; finish the review
- One-paragraph explainer afterward
- Run a separate QE review afterward

---

The host-consent predicate can be sound. **This plan is not ready to implement:** its central premise—that every consent edge represents deliberate human approval—is false in the code, and several security-critical lifecycle rules remain unspecified.

This is a static review of `00d0d37`, the local `v0.1.0` tag, and the supplied Tor source. I did not modify files or run tests. The requested `governance/channel.rs` does not exist; the runtime is `node/channel.rs`.

**1. The strongest attack is through automatic consent, not forged consent.**

A service host joins an existing room through malicious member Mallory. The join path **automatically releases the host’s sender key to the responder and records a consent grant**. Later, the host binds SSH or another service into that room. Under the proposed `readers_of(host)` gate, Mallory immediately receives service access despite never receiving explicit reader approval.

The complete path is present:

- Without a pinned responder, the joiner chooses the board’s first member: [node/actor.rs:1598](crates/vox-core/src/node/actor.rs:1598).
- Joining automatically calls `release_key_to(..., responder)`: [node/actor.rs:1758](crates/vox-core/src/node/actor.rs:1758).
- That function calls `issue_consent`, the same grant mechanism used by explicit approval: [node/actor.rs:1835](crates/vox-core/src/node/actor.rs:1835).

Mallory can be a legitimate passphrase-holding member. **Fixing `learn_members` does not fix this attack.** It contradicts Decision 2’s promise that the specific identity was human-approved and Decision 3’s premise that the relevant human decision already happened.

Conversely, the ordinary vouching attack really does stop at a correctly implemented consent gate. `learn_members` admits self-signed bundle keys, but cannot manufacture the host’s signature. Consent verification binds the author fingerprint to the signing key, and resolution changes that author’s edges only: [consent.rs:184](crates/vox-core/src/governance/consent.rs:184), [evaluator.rs:754](crates/vox-core/src/governance/evaluator.rs:754). I found no basis for claiming an ordinary peer can arbitrarily insert itself into an existing host’s consent set.

Different nodes having different consent views is also **not inherently an authorization bypass**. The serving host must enforce its own current state; a client’s stale belief grants nothing.

An approved reader who should not reach a service is a different problem: the proposal deliberately makes that policy impossible. A contractor approved for design discussions receives every service subsequently bound by that host. That is a substantial least-privilege sacrifice, but [ADR-017:174](docs/adr/ADR-017-room-bound-services.md:174) explicitly accepts it. It is not an undisclosed cryptographic bypass.

**2. Decision 9’s premise is false; its one-layer conclusion can still be correct.**

There are straightforward counterexamples to “holds the descriptor, lacks approval, and knows the name”:

- A **revoked reader** keeps the descriptor and name. Decision 9 itself acknowledges this.
- A **non-member anchor operator** stores the descriptor ciphertext and learns the name from the supposedly harmless bug report.

The anchor explicitly stores room logs without membership, passphrase, or sender keys: [node/anchor.rs:1](crates/vox-core/src/node/anchor.rs:1). Thus “only members sync” is demonstrably wrong.

However, **neither counterexample establishes a need for two encryption layers**. Proper recipient encryption still excludes an unauthorized anchor that knows the name. Tor’s outer layer protects against parties without the address; its inner authorization layer protects against parties without client authorization: [hs_descriptor.c:36](/opt/tor/src/feature/hs/hs_descriptor.c:36).

Also, relaying alone does **not** reveal the proposed service-key name: the relay sees circuit peer identities and carries opaque inner QUIC packets, not the SOCKS hostname: [circuitstream.rs:274](crates/vox-core/src/node/circuitstream.rs:274).

The actual missing proof is **type and metadata hiding**. Today, content and framed governance payloads are publicly distinguishable: [node/channel.rs:539](crates/vox-core/src/node/channel.rs:539). A descriptor-specific tag or distinctive wrapper array reveals its type even when its body is encrypted. The plan specifies neither a common indistinguishable envelope nor a padding rule sufficient for its “cannot learn a service exists” claim. Tor actually pads its client entries with fakes: [hs_service.c:1889](/opt/tor/src/feature/hs/hs_service.c:1889).

**3. `chain_id` is the correct revocation signal, but an insufficient descriptor version.**

The correction is real. `revoke_consent` rotates first and records the resulting generation: [node/channel.rs:1508](crates/vox-core/src/node/channel.rs:1508). `SenderChain::rotated` increments `chain_id` while retaining the channel epoch: [group/state.rs:269](crates/vox-core/src/group/state.rs:269). This agrees with ADR-007.

But the proposed freshness mechanism misses several events:

- **Approving or restoring a reader does not rotate the chain.** `issue_consent` records the current generation: [node/channel.rs:1311](crates/vox-core/src/node/channel.rs:1311). Republishing only when `chain_id` advances leaves the new reader without a descriptor.
- Adding/removing ports, replacing an endpoint, or withdrawing a service need descriptor updates without consent revocation.
- Scheduled sender rotation advances `chain_id` without changing the audience: [node/actor.rs:2887](crates/vox-core/src/node/actor.rs:2887).

The design needs publication triggers and ordering for **every descriptor change**, including multiple versions within one generation. A generation stamp alone also cannot tell a cold client whether an untrusted anchor withheld a newer descriptor.

The channel epoch is wrong as the *sole consent-revocation counter*. It remains necessary as a membership validity boundary. Decision 10’s instruction to republish “on the epoch bump” contradicts its own implementation dependency.

**4. The bare-label impersonation attack is real; a new keypair is not necessary to prevent it.**

If `N` is an unconstrained random label and any host can sign “I serve N,” an approved reader can claim that label under its own identity elsewhere. A service-key signature verified against `N` prevents that impersonation.

It does **not** prevent copying a genuine descriptor. Preventing cross-room transplantation requires the authenticated descriptor to bind the service name, host identity, room, ports, and version. The client must also authenticate the actual transport peer as that named host. The plan leaves that validation contract implicit. Tor explicitly verifies the descriptor’s signing-key chain against the key derived from the requested address: [hs_client.c:2198](/opt/tor/src/feature/hs/hs_client.c:2198).

A cheaper construction is:

`N = H(domain || host_composite_public_key || random_service_nonce)`

The nonce and host key accompany the signed descriptor inside its encrypted body. A reader cannot substitute its own host key while preserving `N`; unapproved members cannot guess the random nonce. This uses the existing composite signer and remains stable across rooms.

A separate keypair may be useful for identity independent of the host, but the cited attack does not establish its necessity.

There is also an unresolved **post-quantum identity choice**: 52 base32 characters encode 32 bytes. Vox’s composite public key is 1,984 bytes: [hash.rs:42](crates/vox-core/src/hash.rs:42). Copying Tor’s raw Ed25519 identity would make service-name authentication classical. The plan needs to specify its algorithm and commitment construction.

**5. “Not a bearer capability” is right. “Without consequence” is wrong.**

Someone approved by the same host in **another room** does not thereby gain access. Decision 3 explicitly scopes consent to the bound room. If the service is also bound to the other room, that reader is intentionally authorized by the union rule.

The existing transport structure supports this separation: requests name a channel, and endpoint lookup is scoped to that channel before authorization: [session.rs:245](crates/vox-core/src/tunnel/session.rs:245). Preserve that property; a global host-reader union would break it.

But a stable name is a **correlation identifier**. An authorized reader in room B who recognizes `N` can associate a public bug report containing `N` with the host/service they know. Publicly posting it also discloses the service’s existence. No encryption scheme can preserve “the unapproved never know it exists” after an approved party publishes its name.

Thus leaking the string need not confer reach, but it can have privacy consequences.

**6. The principal withdrawn-model claims match the tree; other claimed evidence does not.**

Confirmed:

- `serve_room` creates a genesis granting `dial:<port>`: [node/actor.rs:2581](crates/vox-core/src/node/actor.rs:2581).
- The runtime passes `authors.keys()` into the evaluator: [node/channel.rs:935](crates/vox-core/src/node/channel.rs:935).
- The M17.3 gate supplies a member set and **zero governance entries**, then proves successful traffic: [node_m17_up_gate.rs:118](crates/vox-core/tests/node_m17_up_gate.rs:118).
- The local `v0.1.0` tag contains that model; its resolver, authorization wrapper, and M17.3 gate match these files.

So the plan is right about that gate asserting the withdrawn behavior.

However, ADR-013 says its anchor gate was rewritten to use approval. **It was not.** It still invokes `NodeCommand::GrantTunnel`: [node_m15_anchor_gate.rs:660](crates/vox-core/tests/node_m15_anchor_gate.rs:660).

The claimed “new epoch clears every exclusion” behavior also does not follow from the current evaluator. `in_effect` compares an entry’s epoch with its **own causal past**, and exclusion resolution accumulates qualifying historical exclusions without filtering against the head epoch: [evaluator.rs:519](crates/vox-core/src/governance/evaluator.rs:519), [evaluator.rs:797](crates/vox-core/src/governance/evaluator.rs:797). The comment cited by the plan is not proof of the alleged resurrection behavior. Consent folding has the same missing head-epoch filter, which matters to bulk eviction.

**7. Missing lifecycle and integration decisions are substantial.**

**Host removal and departure.** ADR-007 has no administrative single-member eviction; bulk removal is passphrase rotation and rejoin. The plan never defines when a removed host’s descriptors cease to be acceptable, when its bindings disappear, or what happens to existing streams. Nor does it define whether leaving one room preserves the same service in another. These require explicit current-membership and room-binding validity rules, not merely `readers_of(host)`.

**Pending authorization races.** The actor captures a snapshot **before reading the tunnel request**: [node/actor.rs:1315](crates/vox-core/src/node/actor.rs:1315). An approved attacker can open a tunnel stream, withhold its request, wait for revocation, then complete it against the old snapshot. Closing already-spliced connections is insufficient. Revocation must cover pending requests and the interval between checking permission and connecting locally.

**Two hosts offering port 22.** This is not intrinsically a collision: distinct service identities can resolve to distinct authenticated hosts. The current service map is local to each host. But the descriptor/cache key must preserve that distinction. More seriously, the unchanged tunnel request contains only `(channel, port)`, not the new service identity. The plan must define how the requested name remains bound to that tuple, especially after unbinding/rebinding or supporting multiple identities on one host.

**`vox up` and `vox forward`.** Both retain coherent roles: SOCKS for proxy-aware tools, local forwarding for others. Calling them unaffected is wrong. Today `vox up` requires one room and starts an immutable resolver for that room: [cli.rs:332](crates/vox-tui/src/cli.rs:332), [node/actor.rs:2763](crates/vox-core/src/node/actor.rs:2763). The proposed one-proxy experience needs live descriptor updates and room selection. `forward` needs defined service-name or explicit-host semantics and the same authorization checks.

**Upgrade compatibility.** This omission is particularly dangerous. `service_grant` participates in both the genesis signature and the channelID hash: [genesis.rs:245](crates/vox-core/src/governance/genesis.rs:245). Deleting the field changes existing room identities or makes their records unreadable. Retiring `0x0013` does not solve genesis compatibility, retained historical entries, or mixed-version peers continuing the old authorization policy.

**8. Deleting `vox grant` overlooks Bind delegation and expiring access.**

The command is not only an alternative way to grant Dial. It supports `--may-bind` and expiration: [cli.rs:277](crates/vox-tui/src/cli.rs:277). Meanwhile `add_service` still requires `bind:<tag>`: [node/channel.rs:1231](crates/vox-core/src/node/channel.rs:1231).

After removing genesis grants and `vox grant`, how does an ordinary member acquire permission to host? Either Bind authorization survives with an issuance mechanism, or hosting becomes any member’s right. The plan has not decided this, despite promising service hosting in any existing room.

Time-limited maintenance access while retaining chat readership is another real use. A service-specific restriction can compose with consent using **AND**; having two predicates does not inherently create inconsistent authorization. The known membership bug does not prove otherwise.

Also, the claim that the shipped `vox grant` grants access to non-members is overstated: its CLI resolves the target from room members, and the actor rejects targets outside the admitted-author set: [node/actor.rs:2735](crates/vox-core/src/node/actor.rs:2735). The lower-level certificate mechanism is more general.

Deleting redundant Dial grants is defensible **if the coarse policy is intentional**. Deleting the whole command without addressing hosting authority is not.

## VERDICT

**REVISE** — implementable once these issues are fixed, in priority order:

1. Eliminate automatic join-generated service authorization; define which consent acts qualify.
2. Define current membership, host departure/eviction, and revocation covering pending and active streams.
3. Resolve Bind authority and service-name binding through discovery and dialing.
4. Specify descriptor authentication, PQ identity, update/version rules, and achievable metadata privacy.
5. Define compatibility for shipped genesis/log records and mixed-version peers.
6. Update proxy/forward lifecycle requirements and replace the falsely claimed test evidence.