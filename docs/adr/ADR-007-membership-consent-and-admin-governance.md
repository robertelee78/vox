# ADR-007: Membership, Per-Sender Consent, and Admin Governance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted. Built in `crates/vox-core/src/governance/` (M6), `node::channel`, `node::trust` and
`node::actor` (ADR-016 M14.5, ADR-017 M17.6, M17.14, M18.1, ADR-020 M19.2), except:
- Admission once every online member agrees (G-22) is not built: V030-30 (#366). The cap itself is built.
- G-10's golden-vector suite does not exist on this tree, and the known gaps listed at the end are open.

**Proposed for v0.4.20, not accepted or built:** G-6, G-17 and G-21 are amended only as
specified in G-28–G-32 below. Existing accepted requirements remain in force pending decision.

**Date:** 2026-06-19
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

In Signal, Matrix and WhatsApp group membership is not cryptographically authenticated, so one wrong add
exposes all future traffic (the "Signalgate" failure; the Megolm membership-control attacks, Albrecht,
Celi, Dowling and Jones, IEEE S&P 2023, eprint 2023/485). Vox makes reading a per-node, per-direction
cryptographic decision with no central authority: a node is read only by the nodes its owner trusts. The
only room governance is who sets the room's retention. This builds on identity (ADR-002), the join
(ADR-005), Sender Keys (ADR-006) and the causal log (ADR-008).

## Requirements

### §"Trust anchor": the genesis record

- **G-1.** A room MUST begin with a genesis record, its own struct (tag `0x000D`, domain
  `vox/genesis/v2`), with this pinned canonical body:
  `[nonce(16 B random), created, [history_mode, deniability_slot, ttl, min_suite], [service_grant_token…],
  creator_pubkey(composite, ADR-002), [sign_algo]]`, self-signed by the creator's composite identity key.
  `created` and `ttl` MUST be milliseconds (#562).
- **G-1a.** A genesis, admin cert, policy update or lifecycle fact at format 1 (domain `…/v1`), whose
  times are seconds, MUST still be read: its times MUST be held as milliseconds (seconds × 1000), and it
  MUST be encoded, hashed and verified exactly as written, so a room made before keeps its channelID. A
  time MUST NOT be read in the wrong unit.
- **G-2.** The `channelID` MUST be `SHA-256(canonical genesis record)`: 256-bit, self-certifying, bound
  to one genesis. A node MUST accept a genesis fetched from a board only if its hash equals the channelID
  it joined with (ADR-005 J-8). The genesis hash is the channelID, the rendezvous seed (ADR-005) and the
  root of every admin certificate chain.
- **G-3.** The deniability slot MUST be written as `0`, and a genesis with any other value MUST be
  refused: deniable rooms are removed (PRD-001 R43; ADR-009 is withdrawn).
- **G-4.** `min_suite` MUST name a registered ciphersuite (validated at creation and on decode) and is
  bound into the channelID (ADR-003).

### §"Capability vocabulary": the room's governance (V030-32)

- **G-5.** The room's creator MUST be its root admin. Only the creator MAY add or remove an admin, with
  `vox room admin add|remove <member>` (an admin-delegation cert `0x0003` and its revocation `0x000E`).
  A node MUST honour an admin certificate only when the creator issued it, and a delegated admin's
  certificate MUST carry `policy` only, never `admin` (#319). The creator or an admin MAY end the room
  for everyone (`vox room end`, a room-lifecycle fact `0x0019`); every member's node then deletes it
  (ADR-023 RL-8.2).
- **G-6.** The only governance acts MUST be setting the room's retention (the policy-update `ttl`) and
  ending the room (G-5), and only the creator or an admin it delegated MAY do either. The capabilities are `admin` and `policy`; every
  other capability token (`delegate`, `invite`, `passphrase-rotate`, `#role`, `bind:`, `dial:`) MUST be
  refused as unknown. Policy updates beyond retention, passphrase rotation, invite modes and the
  capability lattice are removed, as are `bind:` and `dial:` (PRD-001 R44). **Proposed v0.4.20
  amendment:** additionally permit the room-member removal and readmission acts in G-28–G-32;
  do not introduce a new capability vocabulary.
- **G-7.** A member that is not an admin MAY set a lower retention for its own node only, for one room;
  it MUST NOT set a retention higher than the room's. A node's retention value above the room's MUST be
  ignored (the effective retention is the shorter of the two, ADR-010 AR-30), with a warning (#380).
- **G-8.** The genesis service grant and `service-grant-exclusion` (`0x0013`) are withdrawn
  (ADR-017 decision 3). Wire tag `0x0013` MUST NOT be reused.

### §"Per-type body schemas"

- **G-9.** Every governance entry MUST be a signed entry on the causal log (ADR-008) carrying the author
  identity, the `(channelID, epoch)` binding (ADR-006), a monotonic per-author sequence number, parent
  hash-links, the issuer's certificate-chain reference and a composite Ed25519+ML-DSA signature. Each MUST
  have one deterministic canonical-CBOR serialization (fixed field order, type tag) signed under a
  per-type domain string (for example `vox/cert/admin-deleg/v1`). The bodies MUST be:
  - admin-delegation cert (`0x0003`): `{ delegate_pubkey(composite), capability_set[], expiry?(uint) }`;
  - admin-delegation revocation (`0x000E`): `{ revoked_delegation_hash(32 B), reason?(enum) }`;
  - consent grant (`0x0004`): `{ target_id(composite fpr), skdm_ref(32 B hash of the SKDM delivered over
    ADR-004), history_mode_at_grant }`; the SKDM itself travels in the pairwise session;
  - consent revocation (`0x0005`): `{ target_id(composite fpr), new_chain_id }`;
  - policy update (`0x0006`): `{ ttl }`. The wire layout keeps the `history_mode` and `min_suite`
    presence flags, always written as absent; an update carrying either MUST be refused.

### §"Canonical encoding & evaluator"

- **G-10.** Authorization MUST be decided by one deterministic evaluator: input the requester's
  certificate chain and the room's log; output granted or denied with the governing capability. Two
  correct implementations MUST agree bit-for-bit on the golden test vectors (valid chains,
  over-attenuation, expiry, revoked links, concurrent conflicts). Under ADR-018 these are run on demand,
  not in the build or CI. **Not built:** no golden-vector suite exists on this tree; the in-process
  suite was deleted with the unit tests (V29-17, `df850734`).
- **G-11.** A delegation MUST NOT grant a capability beyond its issuer's (monotonic attenuation). A denied
  verdict MUST carry its classified reason: a delegation killed by an authorized revocation is `Revoked`;
  past `expiry` is `Expired`; an issuer whose chain does not cover the granted set is `OverAttenuated`; an
  issuer with no chain, or a cert bound to an epoch not in force, is `NotAdmin`; the highest-priority
  reason wins (`Revoked` > `Expired` > `OverAttenuated` > `NotAdmin`). A key never named is `NotAdmin`; a
  chain lacking the queried capability is `CapabilityNotHeld`.
- **G-12. (M17.8)** An entry whose body epoch differs from the epoch established in its strict causal
  past MUST be inert (`Evaluator::in_effect`), and that check MUST run before causal position is
  consulted.

### §"Join and per-sender consent flow"

- **G-13.** Trust MUST be per node, held in each node's own keyring (ADR-020 decision 3), and per
  direction. Approving a node is adding it to the keyring (`vox trust add`); from then on it reads this
  node in every room they share, including rooms made later. There MUST NOT be a per-room consent step:
  a consent grant scoped to one room is not part of the model. Trust is one-sided, and a client MUST say
  so where trust is added.
- **G-14.** Every consent grant MUST be caused by a keyring entry. A node MUST release its sender key only
  to a member its owner's keyring trusts, checked in the core (V210-148).
- **G-15.** The join flow MUST be:
  1. `N` joins (ADR-005) and opens pairwise sessions (ADR-004) with the members it meets. Holding the
     room's credentials releases no sender key, so `N` reads nothing yet.
  2. `N` decides which members read `N`, by trusting them. Joining MUST NOT release `N`'s sender key to
     anyone (M17.6). The joiner opens its session with `PairwiseFrame::Open`, one sealed message with an
     empty plaintext, so the responder gains a sending chain and receives no key and no grant.
  3. Each member `A` decides whether `N` reads `A`, by trusting `N`. Until `A` does, `A`'s messages stay
     unreadable to `N`. `N`'s view fills in monotonically, per sender.
- **G-15a. Release at admission.** When a joiner is already in a member's trust keyring, that member
  MUST release its sender key to the joiner when it admits the join, not on a later tick: the room is
  forward-only, so anything sealed before the release would stay unreadable to the joiner for good.
- **G-16.** A grant MUST record what it released (`history_mode_at_grant`): the granting owner's choice
  per grant (ADR-006 S-18), never another member's history.
- **G-17.** Log authorship and read authority MUST stay separate: `admit_author` records a verified key
  as a log author, which lets its entries pass the ADR-008 predicate and nothing more; its content stays
  ciphertext until its sender key arrives. Keys come from the verified genesis, admin certificates or the
  board's records (ADR-016), never from a server-supplied list. There is no admin-issued membership
  certificate and no roster. **Proposed v0.4.20 amendment:** author admission alone does not override
  a room-member removal; G-28–G-32 add authoritative room-bound negative and readmission facts.
- **G-18.** A member reaches a room-bound service when it is in the host's keyring and in the room the
  service is bound to, both checked at dial time (ADR-017 decision 3). A member the host has not trusted
  MUST reach nothing; a trusted identity that later joins gains reach on joining. The trust surface MUST
  state this scope when trust is added, and `vox serve` MUST name who can reach the service (ADR-017
  decision 4).

### §"Revocation and epochs"

- **G-19. (M17.14, M18.1)** Removing a node from the keyring (`vox trust remove`) MUST change the lock in
  every room shared with it: rotate this node's sender key (advancing its own `chain_id`, not the room
  `epoch`), record a consent-revocation fact naming the generation that excludes it, and re-key every
  member still trusted at the new generation's origin. Revocation is rotation with one member left out;
  there is no second mechanism.
  - The keyring edit, the rotation and the log fact MUST land first and unconditionally, with no network
    needed; the re-keys follow best-effort and the tick MUST retry them.
  - The node MUST also drop the removed node's keys in every room, so it stops reading it (V210-118).
  - A room closed at the time MUST do both when it next opens (V210-118).
- **G-20.** `epoch` MUST be a single room-global counter; per-author rotation is always `chain_id`.
- **G-21.** There MUST be no per-room visibility opt-out and no admin removal of a member: a node stops
  reading a member, and stops being read by it, by removing it from its keyring (G-19). Passphrase
  rotation is removed (G-6). **Proposed v0.4.20 amendment:** replace the prohibition on admin
  member removal with G-28–G-32. Room removal is distinct from both a per-node visibility opt-out
  and global keyring removal; passphrase rotation remains removed.

### Member cap

- **G-22.** A room MUST NOT exceed its member cap (`MAX_AUTHORS` = 1024). A newcomer MUST be admitted only
  once every member that is online has agreed (V030-30, #366). The member answering a join MUST, before it
  sends `ACCEPTED`:
  1. hold a place for the joiner, refusing with `FULL` when its authors reach the cap, or with `TAKEN`
     when its authors and the places promised and not yet settled fill it;
  2. ask every other member of the room it holds a connection to, all at once, on a stream typed `seat`
     (`StreamKind::Seat`), whether the joiner may take a place;
  3. admit the joiner only if every one of them answered `YES`; otherwise send `ABORT` to each member that
     said `YES`, free its own place, and refuse the joiner with `FULL`, `TAKEN`, or `NOT_AGREED` naming
     the member that did not agree.
- **G-22a.** A member asked MUST count its authors and every place promised and not yet settled, its own
  and those it promised other members, other than the joiner's own, and answer `FULL` at the cap, `TAKEN`
  when promises fill what is left, or `YES`, promising the place. A promise MUST count until the joiner is
  an author on that member, an `ABORT` from the member that asked frees it, or `PROMISE_TTL` (120 s)
  passes. A stream that ends without `ABORT` MUST NOT free the place.
- **G-22b.** A member that does not answer within `SEAT_ANSWER_WITHIN` (5 s) MUST fail the join, named.
  A member the answering member holds no connection to MUST NOT be asked and MUST NOT block the join; it
  learns of the newcomer when it returns. Anchors that are not members MUST NOT be asked.
- **G-22c.** Two newcomers asking for the last place at the same moment MAY both be refused `TAKEN`, and
  each MUST be told to try again. No join MAY report success unless the joiner was admitted.
- **G-22d.** The only way past the cap MUST be a split: a member another member admitted MUST be admitted
  from the board even past the cap, up to `AUTHORS_HARD_LIMIT` (2048), and this MUST be logged.

### §"Conflict resolution"

- **G-23.** Governance state lives on the causal log (ADR-008) and relies on its fork handling. An
  authority action made during a partition MUST be provisional until its causal neighbourhood reconciles.
- **G-24.** Consent MUST be single-writer: only `A` authors `A`'s grants, revocations and sender-key
  rotations, so `A`'s latest causal state wins. Additive facts (grants, delegations) MUST all stand,
  ordered causally.
- **G-25. §"Removal beats addition"** A revocation of an admin delegation concurrent with or after that
  delegation MUST make the key not an admin until a causally later re-delegation. A key MUST be an admin
  iff a valid delegation chain to genesis grants it and no causally later authorized revocation supersedes
  it.
- **G-26.** Among the causally maximal concurrent delegations of one delegate, the governing one MUST be
  the last in the canonical total order: Kahn's algorithm over the causal relation, always emitting the
  smallest-hash ready entry (`Causality::build`). An independent implementation MUST reproduce this order.

### §"Enforcement honesty"

- **G-27.** Only forward guarantees are cryptographic: rotating to keys a party never receives is
  enforced; keys a party already holds MUST NOT be described as recalled. A removed node keeps what it
  already read. Retention and erasure are honoured by clients (ADR-010).

### Proposed v0.4.20 — room-scoped member removal (not accepted or built)

- **G-28. Authority and scope.** The creator or a currently authorized delegated admin MAY remove
  one particular non-creator node member from one room; an ordinary member MUST NOT do so. The
  creator's root identity MUST NOT be removable. This is neither `room admin remove` (which revokes
  a delegation) nor `trust remove`: it MUST NOT mutate any global trust, computer approval or
  membership, keys or access in another room. A replacement fingerprint is a different node and
  inherits no authority from the removed identity. An admin whose own membership is removed MUST
  NOT exercise its delegation while removed; removal alone MUST NOT silently revoke that delegation.
- **G-29. Signed authority and ordering.** A removal MUST be an authenticated governance-log
  fact using G-9's canonical encoding, composite signature, channel/epoch and author/causal
  bindings. The proposed appended tags, unallocated in the source registry through `0x0023`,
  are removal `0x0024` with signing domain `vox/member-removal/v1`, and readmission `0x0025`
  with signing domain `vox/member-readmission/v1`; both use frame version `1`. The canonical
  unsigned CBOR arrays are respectively `[channel_id, epoch, issuer_id, target_id]` and
  `[channel_id, epoch, issuer_id, target_id, removal_entry_hashes]`: IDs and hashes are 32-byte
  byte strings, epoch is an unsigned integer, and the nonempty removal hash array is unique and
  sorted by bytewise hash. Each framed wire array appends the composite signature bytes to its
  unsigned fields; the signature covers the domain concatenated with the unsigned canonical body.
  The issuer MUST equal the enclosing log author; channel and epoch MUST match that entry and
  the epoch in its strict causal past. References identify enclosing governance log entry hashes.
  ADR-008's registry MUST be updated when this proposal is implemented; reserved old tags MUST
  NOT be reused.

  The creator is root admin; a delegated remover MUST have an unexpired, in-effect,
  creator-issued delegation granting `policy` in the action's strict causal past, and MUST
  itself be a member at that action. Evaluate this authority in the strict causal past,
  not by a circular final-membership predicate, with one root-authority cutoff: a delegated
  admin's governance act must, for every valid creator removal of that admin or revocation
  of its delegation, either lie in that creator fact's strict causal past or descend from a
  valid root-only re-enabling fact which itself descends from that cutoff: creator readmission
  for removal, or a fresh creator delegation for revocation. Otherwise it is invalid and kept
  only as opaque evidence. Restored authority also requires ordinary current membership,
  scope and delegation checks. Acts citing only pre-cutoff parents remain invalid after
  restoration. Root-only cutoffs and restoration introduce no mutual-validity cycle.
  Concurrent removals by two delegated admins can both stand; absent a creator cutoff,
  a malicious removed delegated admin can still issue concurrent governance using old
  parents. That disclosed limit is resolved by creator removal or delegation revocation,
  not by pretending delegated removal is root revocation. Later actions must honor their
  own causal-past authority as well as any validated creator cutoff.
  Readmission requires the creator's root signature, not delegated `policy`. Retain necessary signed
  ancestry and delegation evidence. A board Member withdrawal alone is discovery evidence, not
  this fact or authority to alter the log. Replays MUST be idempotent; wrong-room, invalid,
  unauthorized or missing-ancestry facts MUST NOT grant access or effect removal. Missing or
  unvalidated dependencies remain inert, not a room-wide egress barrier; re-evaluate the fact
  when ancestry arrives.

  The global v0.4.20 protocol cutover in ADR-011 is a prerequisite, not a per-room
  capability negotiation: every currently participating or reachable peer, including a board,
  MUST negotiate the applicable `vox/3` ALPN and prove its node identity before any room
  mutation or data exchange. Refuse old-protocol connections at transport, without calling the
  refusal a bad passphrase or an unreachable anchor. No acknowledgement from an offline legacy
  or retired member is required to remove it. An offline old peer cannot receive future keys or
  sync from the new cohort until updated and its current governance fold is applied. An unaware
  partition may continue under old rules; this cutover does not promise instant global revocation.
  Direct and no-anchor rooms remain supported; no mixed-version compatibility is assumed.
- **G-30. Readmission and conflicts.** Only the creator MAY explicitly readmit the exact removed
  fingerprint, by a distinct signed room-bound governance fact referencing all removal facts it
  supersedes. It MUST causally descend from every removal it supersedes; an ordinary passphrase
  join, board record, prior admission, retained trust or replacement identity MUST NOT undo removal.
  Evaluate the complete validated causal set: any valid removal not causally superseded by a valid
  creator readmission keeps the target removed, including a concurrent removal and readmission.
  A later removal wins again. Replays and delivery order MUST converge on the same result; use
  G-26's canonical order for otherwise concurrent presentation, not to turn concurrent readmission
  into authority. Readmission is subject to ordinary admission/cap and trust checks and grants no
  sender, Drive or service authority by itself.
- **G-31. Forward enforcement.** Before irreversible room egress, each member MUST check current
  validated room authorization and fence stale in-flight work against the current room authorization
  generation; an applied, validated removal MUST win over queued sends, key delivery, Session
  read/Drive and service access. Once applied, exclude the target from active membership, claims,
  reach and new access; rotate future sender keys and applicable room-bound Drive and service
  keys/credentials and distribute them only to still-authorized, independently trusted nodes.
  Close or reauthorize existing affected sessions. Catching up peers MUST apply the barrier before
  resuming egress, including after restart.

  For each validated removal, a target-authored public log entry is historical if it is in that
  removal's strict causal past. For any removal not in the entry's causal future, the entry is
  eligible only if it causally descends from a valid creator readmission that supersedes that
  removal. Thus concurrent entries and entries after removal but before readmission are not
  authorized by earlier membership; a removal concurrent with or later than a readmission wins.
  This eligibility filter applies to application messages, keys, consents and claims,
  public Presence/Session metadata and services, not governance validity or off-log Session
  records. Once a removal is known, members MUST NOT decrypt, accept or forward as content,
  display, or give authority to ineligible
  content, including replays and entries received before the removal became known. Recompute
  visibility when new validated causal evidence arrives. These rules apply per removal and
  readmission, not by wall clock or arrival order. Deny the removed target's sender keys during
  removal, including replayed keys; after readmission apply ordinary consent and fresh-key checks.

  **Private Session records (proposed clarification, pending review).** Off-log records have
  no public Entry ancestry. Enforce ADR-031 SA-14 through the existing signed public Session
  floors; do not invent chronology from first-seen time, add per-activity public entries, or
  introduce a second record/envelope authority. Keep existing private record versions and
  key-message bytes. For a once-removed author, new acceptance requires an eligible floor
  descending from covering creator readmission, and a drive generation strictly greater than
  every generation that author floored outside that restoration's causal descendants.
  An author MUST rotate after applying its own readmission and issue new eligible floors.
  A recipient's historical floor is not current access: release/serve requires its current
  restored membership and ordinary trust/Drive, with a floor either historically prior to
  its removal or descending from covering readmission as SA-14 specifies.
  Deny removed-author keys, `current_drive` and locally-held legacy bypasses; fence queued
  key/Drive/service work at the current room authorization generation. Preserve exact signed
  floor provenance and necessary ancestry for re-evaluation, not just folded maxima.
  Already locally accepted private rows remain readable under the reader's current ordinary
  permission, but confer no live authority and may be re-served only under SA-14. This local
  history boundary depends on arrival order, not a global causal fact; new peers may not
  acquire private rows excluded by the current floor rules. Disclose that limitation and
  the unaware-partition window in release notes.

  Governance validity uses G-29's strict-causal-past authority plus its creator-precedence
  cutoff, not the recursive final-membership predicate. Concurrent mutual delegated-admin
  removals remain valid unless the applicable creator cutoff invalidates an act. Creator
  removal or delegation revocation invalidates concurrent/later delegated governance,
  including room end, rename, retention, anchors and further removals, unless the act
  descends from the appropriate valid root re-enabling fact under G-29. Choosing old
  parents cannot evade a cutoff before or after restoration. Members MUST retain and
  forward ineligible signed skeletons and ciphertext as opaque causal-parent/fork evidence,
  without applying content or authority.

  Retain historical signed entries, their signatures, author-chain skeletons, fork evidence and
  claim history; filtering is not deletion of the target's prefix or a rewrite of signed history.
  A partitioned peer cannot know an unseen removal: do not claim instantaneous global revocation;
  show local applied versus pending/unknown propagation honestly. Previously disclosed plaintext
  and keys cannot be recalled or made retroactively secret (G-27).
- **G-32. Consumer acceptance.** Extend existing real product journeys with isolated nodes and
  native UI/CLI: identify the target by verified exact fingerprint, show before and after effects
  and room scope, and remove it as creator and delegated admin; non-admin and creator-target
  attempts fail. An independent online peer and an offline peer catching up must apply the signed
  removal, retain readable signed history, and exchange distinct new posts without the removed
  node reading them or using future room-bound Session read/Drive or services. The retained
  passphrase, old records and concurrent/replayed readmission cannot bypass removal; an explicit
  creator readmission followed by ordinary authorization restores only appropriate access.
  Demonstrate unrelated rooms and global trust remain unchanged, including a same-name replacement
  fingerprint. Exercise stale queued egress and removal/readmission permutations through actual
  consumers. After a creator removes or revokes a delegated admin, submit attacker-crafted
  governance with pre-cutoff parents: concurrent/later end, rename and member-removal acts
  stay inert regardless of delivery order, including through an unaware peer. Prior valid
  acts remain historical; mutual delegated removals converge without recursive validity
  oscillation. Revoke then re-add, and remove then readmit, restore governance for new acts
  descending from the appropriate root restoration; forged acts citing only pre-cutoff parents
  remain inert after restoration. The apparatus is isolated profiles, controlled partition
  and timing; the PRODUCT verdict is observed membership and access, not a log assertion or
  successful command alone.
  Separately have the removed node post, including a partition-concurrent post replayed after
  catch-up; independent peers' native views MUST NOT show those posts, while the causally prior
  signed history remains readable. Exercise eligible post-readmission content separately.
  Independently exercised mutants that omit the egress barrier, accept and display a removed
  author's post, or let passphrase rejoin override removal MUST each make the corresponding
  consumer proof fail. These are future proofs, not results.

### Known gaps

- `history_mode_at_grant` and `new_chain_id` are recorded but never validated by the evaluator.
- The golden-vector suite is in-process Rust assertions, not language-neutral fixtures with pinned bytes
  (the "two independent implementations" gate needs the latter). Since V29-17 (`df850734`) there is no
  suite at all (G-10).

## Consequences

- The single-wrong-add exposure is gone by construction: nothing is readable without the reader's trust.
- Governance is serverless and client-verifiable; every admin claim chains to the genesis.
- Removing a node costs O(remaining trusted members) of SKDM redistribution, in every shared room.
- Removal-wins can briefly hide a legitimately re-added admin until the re-delegation propagates.
- A room near its cap is joined only as fast as its online members answer (G-22).

## Related ADRs

Depends on ADR-002, ADR-005, ADR-006, ADR-008. Depended on by ADR-010, ADR-013, ADR-014, ADR-017,
ADR-020, ADR-023. Cited: ADR-003, ADR-004, ADR-016, ADR-018. ADR-009 (deniable mode) is withdrawn.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
