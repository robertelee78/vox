# ADR-035: Computer trust and daemon identities

**Date**: 2026-10-12

**Status**: Accepted for v0.4.5: product requirements and technical contract revision 2.
The product requirements come from the decider's Q&A on 2026-10-12. The technical contract has
independent GO as recorded below; implementation and product acceptance remain outstanding.
Nothing in this ADR is built.

**Deciders**: robertelee78

**Tags**: daemon, identity, computer-trust, pairing, keyring, drive, macos, linux

## Context

Three computers with three or four nodes each make individual reciprocal trust a repeated
operator task. ADR-031 removes the work between eligible nodes of one daemon, but deliberately
leaves remote trust individual. A presented node name (#796) makes a fingerprint recognizable;
it does not remove the repeated trust decisions between computers.

The decider chose two ways to trust: a computer's managed nodes together, or individual nodes.
His rule: "I either trust at the computer level or I trust at the node level. If I trust at the
computer level that means all of its nodes are trusted". Computer trust follows changes to the
daemon's nodes. There are no per-node exceptions while that computer is trusted.

## Terms

A **computer**, in this feature, is one Vox installation's daemon and data root (ADR-026 D-1),
normally one OS account. Its authority does not extend to another account's or data root's nodes
on the same physical machine. The app MUST make multiple installations distinguishable.

**My computers** is the group explicitly established through computer pairing. Adding a computer
through one member includes it for the other members; it is not necessary to pair every pair.
Trusting an individual node does not enroll its daemon or introduce other computers.

A **personal node** is the node selected in that computer's Vox.app. This is a saved selection,
not an intrinsic human/agent identity type. **Other nodes** means that daemon's remaining nodes.
A headless computer such as Beast can be enrolled without a personal node; the selected personal
nodes on the Macs can drive its other nodes. No node is to be guessed to be personal from its name.

## Requirements

### 1. Identity and the two trust modes

- **CT-1.** A daemon MUST have its own persistent authenticated identity for computer pairing and
  management. It MUST survive ordinary daemon restarts, application updates and node renames.
  A computer name or network address MUST NOT stand in for that identity. The daemon's identity
  MUST NOT turn it into a chat node or a member of a room; existing node identities remain the
  identities used for room communication and drive.
- **CT-2.** Individual node trust MUST remain available without computer pairing, with its existing
  read and read + drive choices. Trusting a node MUST NOT imply trust in its daemon, other nodes
  of that daemon, or other computers.
- **CT-3.** Computer trust MUST cover all current and future nodes managed by the enrolled daemon.
  For the computer group, every node MUST have read trust in every other node; every personal
  node MUST receive drive over the other, non-personal nodes. Other nodes MUST NOT receive drive
  automatically. The personal selections of all computers, not just this Mac's, determine this
  policy. Computer mode MUST have no per-node exclusions or individual permission overrides.
  Read trust still applies within the existing room protocol: it MUST NOT give an unjoined node
  access to a room or bypass a session's repository binding.
- **CT-4.** The app and operator CLI MUST say whether trust comes from computer mode or individual
  node mode. A per-node action that contradicts an active computer policy MUST explain that the
  person must stop trusting the computer before choosing individual nodes. Changing modes MUST
  show the resulting permission changes before confirmation; it MUST NOT hide leftover individual
  grants as exceptions to the computer policy. While computer mode is active, CT-3 MUST be the
  effective policy even where an earlier individual grant was stronger. How the previous records
  are represented is a storage-design choice; their retention MUST NOT preserve extra permissions.
- **CT-5.** A daemon MUST provide an authenticated roster of its managed node fingerprints and
  presented names, and its saved personal-node selection. Enrollment and roster changes MUST be
  bound to the correct daemon identity; a node name, copied fingerprint, proximity or shared
  room membership alone MUST NOT establish management of a node. Local aliases follow #796:
  a local name the person chose MUST survive later presented-name changes.

### 2. Pair once, including a computer without the app

- **CT-6.** The primary flow MUST begin with **Add Computer** in Vox.app. It MUST provide a one-time
  pairing code usable in the other Mac's app, or one command for the operator to run in a
  headless computer's terminal. It MUST show the computer's name and the computer trust policy
  for confirmation once; it MUST NOT ask the person to trust every node separately. The exact
  protocol and command spelling are to be designed, not invented by this ADR.
- **CT-7.** Pairing MUST authenticate the two daemon identities and the approved enrollment.
  A pairing code MUST expire, be cancellable and be consumed once. Pairing failures MUST say
  what did not complete and MUST NOT report computer trust as established before it is established.
  Pairing is the person's action in Vox.app or an operator terminal; an agent process MUST NOT
  create or widen computer trust, enroll a computer, or choose a personal node for itself.
- **CT-8.** Adding Beast through a work Mac already grouped with a personal Mac MUST add Beast
  to that same group. The personal Mac MUST learn the authenticated enrollment and apply CT-3
  without a second pairing ceremony. This authority comes from the explicit computer-group
  relationship; an arbitrary node's keyring is not a source of group membership.
- **CT-9.** The group MUST keep working when the computer used for the original pairing is
  unavailable. An offline member MUST receive pending approved changes when it reconnects;
  the app MUST distinguish confirmed state from changes still pending at an unreachable member.
  The ordering and reconciliation rules are required design work under CT-22.
- **CT-10.** Pairing MUST establish trust only. It MUST NOT join rooms, copy room passphrases,
  create or change repository bindings, or reroute a session's conversation. A node still needs
  the relevant room membership and session binding. ADR-029 RB-3/RB-4 and #795 remain in force.
- **CT-11.** Existing direct reachability MUST remain sufficient. A pairing MUST NOT wait on or
  fail because of an anchor when its peer is directly reachable (ADR-012 N-1–N-8). When an anchor
  is needed, pairing MUST use authenticated reachability and report a reachability failure
  separately from a rejected or expired pairing code. Nearby discovery is not the primary flow.

### 3. Keep trust current as nodes change

- **CT-12.** Creating or removing a managed node MUST update the authenticated roster and the
  computer policy on the other enrolled computers without another operator trust decision.
  Removing a managed node MUST remove the grants supplied by that roster membership. Renaming
  one MUST preserve its fingerprint and the person's local aliases; a replacement fingerprint
  MUST be represented as a changed identity, not silently treated as the old node.
- **CT-13.** The daemon MUST know and persist the node selected in Vox.app. Closing the app MUST
  NOT revoke or forget that selection. When the person selects another node in Vox.app, the
  daemon MUST communicate the change and move the automatic drive permissions to the newly
  selected personal node. The previous selection MUST lose those automatic drive permissions;
  CT-3's read policy remains. Multiple Macs may each have their own personal node.
- **CT-14.** Updates MUST be authenticated, ordered and applied idempotently. A stale roster or
  personal-node announcement MUST NOT restore removed membership or old drive privileges.
  Restarting either daemon MUST NOT undo the last accepted policy. Interrupted reconciliation
  MUST be recoverable without requiring the person to repeat fingerprint-by-fingerprint trust.
- **CT-15.** The app MUST show which computers and nodes participate, which personal nodes have
  drive, and whether the requested changes have reached each computer. An unavailable computer
  MUST NOT be shown as having acknowledged an update. The operator CLI MUST expose the same
  effective policy and pending state for a computer such as Beast.

### 4. Stop trusting a computer

- **CT-16.** Removing a computer from My computers MUST remove all trust in its managed nodes
  across the remaining group, including individual node grants the person made before pairing.
  It MUST NOT preserve those earlier grants as exceptions. The confirmation MUST state this
  effect plainly and name the affected computer and nodes.
- **CT-17.** A removed computer MUST NOT return through a stale roster, restart, reconnect or
  another existing member's old view. Including it again requires a new deliberate enrollment.
  Once computer trust is absent, the person MAY instead establish individual node trust again.
- **CT-18.** Remaining members MUST enforce removal when they receive it; the app MUST show
  removal as pending at an offline member until confirmed. It MUST NOT claim that it erased
  data already held by the removed computer or changed the keyring of an unreachable computer.
  Existing read/drive revocation behavior applies to connections and Sessions, rather than
  merely deleting the computer's row from the app.

### 5. Design, upgrade and product proof

- **CT-19.** The upgrade MUST preserve existing individual node trust, aliases, identities, rooms,
  repository bindings and data until the person explicitly enables computer trust. An upgrade
  MUST NOT infer a computer group from existing trust, names, shared IP addresses or room members.
- **CT-20.** Any on-disk change MUST follow ADR-026 F-3: automatic upgrade from every supported
  release since v0.4.0, proved on a data root the published v0.4.4 binary wrote. Computer identity,
  group membership and policy storage MUST be coordinated with #741's one v0.4.5 format step;
  this feature MUST NOT invent an independent second format raise. Earlier peers that do not
  support computer trust MUST remain usable through individual node trust, with support stated
  accurately. The design must settle the new control protocol's compatibility before building it.
  The pairing implementation owns its new data and upgrade contribution to the existing journey;
  #741 owns final acceptance of the combined release upgrade. Contributors are to integrate with
  that contract, not wait for the entire combined proof before they can implement their part.
- **CT-21.** Validation MUST extend existing real app/CLI/daemon/drive journeys, using scratch
  VOX_DATA_DIR and VOX_CONFIG_DIR. It MUST exercise two Macs' personal nodes plus a headless
  computer, one enrollment bringing the third into the group, a newly created and removed node,
  an app selection change while another computer is offline, restart/reconnect, complete removal
  including a former manual grant, continued individual node trust, and unchanged room bindings.
  Assertions MUST concern visible state and actual read/drive outcomes. Each proof needs a
  mutant that turns its own product assertion red; inability to stage a case is APPARATUS.
  ADR-018 holds: no unit or mechanism gates, no gratuitous repeats, app evaluations and live-model
  spikes remain optional, and the release's upgrade proof is extended rather than duplicated.
- **CT-22.** Before implementation, the design MUST settle daemon-key protection and lifecycle;
  authenticated enrollment and proof of node management; authority for group additions, removal
  and personal-node changes, including authority exercised by a non-founding member and the
  consequences of a compromised member; update ordering and offline convergence; lost/replaced
  installations and duplicate restored identities; computer-name ownership, local aliases and
  collisions; the storage lifecycle of earlier individual grants under CT-4/CT-16; the exact
  pairing flow; and the shared migration and older-peer behavior. It MUST follow the existing
  cryptographic policy rather than choose a new cryptosystem
  as a side effect of this feature. These are technical design obligations, not permission to
  reopen the product decisions above or to mark implementation stories Ready without a design.

## Accepted technical contract

The [revision-2 technical contract on #798](https://github.com/robertelee78/vox/issues/798#issuecomment-6137614328)
settles CT-22's identity, pairing, causal membership, fork, policy-journal, transfer/recovery,
retained-history, compatibility and shared-upgrade design. It has an
[independent GLM-5.3 GO](https://github.com/robertelee78/vox/issues/798#issuecomment-6137677323).
That contract governs implementation; CT-1 through CT-22 remain the product requirements.
The following clarifications delimit its changes to earlier ADRs:

- The daemon MUST have a separate computer-management identity using the existing composite-key
  software vault, with an empty passphrase for unattended operation. Its private directory under
  `.daemon/computer` MUST have mode `0700` and its owned files mode `0600`, with atomic install,
  ownership and symlink checks, and no secret logging. Its protection is the OS-account boundary;
  it does not protect against a copied data root or a compromised account. This vault MUST remain
  distinct from node vaults and MUST NOT change their passphrase or lifecycle rules.
- The management identity MUST register as a distinct role on the daemon's existing
  `SharedEndpoint`, one QUIC endpoint and one UDP socket, including when zero nodes are attached.
  It MUST NOT create a second network presence or dispatch node/room streams. The daemon remains
  outside rooms; node identities remain the authority for room communication and drive.
- A node-management binding MUST be signed by both the node and its managing computer according
  to the contract; it confers computer-policy authority only through explicit computer enrollment.
  It asserts opted-in management within that group, not a link to physical hardware, other data roots
  or a human identity. Vox MUST NOT present it as physical-device attestation. A copied node vault
  alone MUST NOT establish or transfer management authority.

Technical GO is design acceptance. CT-21's actual product journeys and CT-20's migration
contribution remain required; #741 still owns the combined release-upgrade acceptance.

## Superseded and amended lines

These are narrow successor amendments. Requirements not named here remain in force; the
predecessor ADRs' node, room and transport rules are not otherwise replaced.

| Existing rule | Amendment for computer management and explicitly enrolled groups |
|---|---|
| ADR-026 D-2: the daemon holds no identity key | Supersede only the no-identity-key clause: the daemon MUST hold the separate persistent computer-management identity (CT-1 and the accepted contract). It MUST NOT be a node or join rooms and MUST run with zero nodes attached |
| ADR-026 D-3: one UDP socket and one QUIC endpoint per data root | Preserved: the management identity MUST use a distinct role on that same daemon-owned endpoint and socket, never a second network presence or node/room dispatch role |
| ADR-010 AR-5: a generated identity vault is wrapped under an identity passphrase | For the separate unattended computer-management vault only, the existing software vault MUST use an empty passphrase and the OS-account protection specified above. Node-vault and room-store protections remain unchanged; no hardware or copied-root protection is claimed |
| ADR-002 D1: Vox does not attest a link between a device and an identity | Opt-in, node-and-computer-signed management bindings MAY establish group management membership under CT-5 and the accepted contract. They MUST NOT attest physical-device ownership or hardware identity. Nodes remain separate identities, and ordinary individual trust establishes no management relationship |
| ADR-020 10.1 and ADR-031 LT-3: no remote identity vouches for others in granting read | An explicitly authorized computer-group policy may use authenticated daemon rosters; ordinary node trust still introduces nobody (CT-2/CT-5/CT-8) |
| ADR-031 LT-7: nothing automatic for nodes on other machines | Computer trust is the explicit alternative; individual remote node trust remains available (CT-2/CT-3) |
| ADR-031 LT-6: a removed local automatic pair stays removed | Unchanged outside computer mode; computer mode has no per-node exception and removal is at computer scope (CT-4/CT-16) |
| ADR-031 LT-8 and #677: agents cannot widen trust | Extended to computer enrollment and personal-node selection; the user-approved daemon policy supplies routine roster updates (CT-7/CT-12) |

## Implementation order and related work

The accepted revision-2 contract settles CT-22 and the shared design boundary with #741.
Implementation is to begin with authenticated two-computer pairing and its two trust modes,
followed by group enrollment without repeated pairings, ongoing roster and personal selection
changes, and complete removal. Group updates and removal MUST use that same membership design
and daemon-owned transaction domain, not competing state stores. Each implementation story still
requires its approved handoff and scoped acceptance; the design verdict is not product acceptance.

#724/#725 still own automatic trust between eligible local nodes outside computer mode. #796
owns presented node names and local alias preservation. #677 owns the common operator-only trust
boundary. #741 owns the release's combined format step. #794 owns the installed skill's real-work
behavior, and #795 owns repository/room isolation. This ADR must integrate with those outcomes,
not duplicate or silently replace their implementation work.

Depends on ADR-002, ADR-003, ADR-010, ADR-012, ADR-018, ADR-026, ADR-028, ADR-029 and ADR-031. Amends the
lines listed above. Pairing does not require a new room, a central account service or new room
membership. It is not a claim that the whole physical computer or every OS account shares one
daemon identity.

## Consequences

The person approves a computer group once instead of repeatedly granting every node pair.
New nodes and app selections follow the same visible policy. Individual node trust remains the
choice when the person does not want to trust an entire Vox installation.

Computer trust intentionally gives broader authority than individual node trust. The roster,
personal selection and group removal are authorization state, not advisory telemetry. Their
authentication, recovery and upgrade design are prerequisites to a safe, understandable product.
