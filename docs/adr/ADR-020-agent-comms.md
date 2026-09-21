# ADR-020: Agent comms — a room-based messaging app on the Vox layer

**Status**: **partly implemented** (2026-09-21). **Decision 3's trust keyring is built and merged**
(M19.2: `node::trust::Keyring`, `NodeCommand::{Trust,Untrust}`, `NodeView::trusted`,
`ChannelState::owed_consents`, auto-consent retried on the tick), and **decision 1's crate now exists**
(M19.3, the envelope + claim rules). The rest — decisions 2 and 4–9 — remains proposed. An earlier status
line said "nothing in this ADR is implemented. The crate it names does not exist yet" after both had
landed; corrected here.

**Decision 3 was also generalised the same day** and is no longer an agent-comms mechanism: the keyring is
Vox's **only** way to grant read access, for people as much as for agents. See decision 3.
**Date**: 2026-09-21
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: agent-comms, app-tier, node, ipc, consent, keyring, harness-integration

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** and **MAY** in this
document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174).

## Context

Vox is a networking layer with applications riding on it. The decider named three: **chat** (text
today; voice, video and file exchange later), **room-bound services** (ADR-013/017, built), and
**agent comms** — this ADR.

### The app tier does not exist

Today there are two tiers, not three. `vox-core` is the layer, `vox-tui` is the UX, and chat's
semantics are **fused into the layer**: `node/content.rs` *is* chat's message format, and
`node/channel.rs` holds chat's consent rules. That was correct with one application. Agent comms is
the second, and a seam is invisible with one app and unavoidable with two.

### What exists today, and why it is clunky

The decider currently drives agents through `claude-telegram-mirror` (ctm): one Telegram forum topic
per agent session, a daemon and bot per host. ctm solved the hard per-host problem — attaching to a
live session — three times over, and those seams are reusable:

| Seam | Claude Code | Codex | OpenCode |
| --- | --- | --- | --- |
| Observe | 7 hooks → `ctm hook` → NDJSON over a Unix socket | app-server JSON-RPC over WebSocket over a Unix socket | `/event` SSE, or an in-process plugin |
| Deliver | `tmux send-keys`, confirmed by `capture-pane` | `turn/start` when idle, `turn/steer` when running | HTTP API |
| Decisions | `PreToolUse` blocks ≤ 5 min on a button | server requests answered on the same JSON-RPC id | `permission.*` / `question.*` |

But Telegram is doing **three jobs at once** — transport across NAT, human UI, and durable log — and
agents never see each other. A topic is a private line and the human is the only router. Driving two
agents on two machines therefore degrades into ruflo federation plus a double SSH tunnel: ADR-111
states outright that it omits NAT traversal, so those tunnels are a human doing Telegram's transport
job by hand, and its pairwise peer model is a human doing a room's job by hand.

Vox already replaces all three Telegram jobs: the reachability ladder and anchor for transport
(ADR-012), the room for rendezvous, and the converging authenticated log for durability (ADR-008) —
with PQ end-to-end confidentiality that Telegram cannot offer.

### What this room is *for*

The decider was explicit, and it bounds the whole design:

> if we had n-count agents in a vox room all chattering away like they do in ctm, it would be such a
> wall of shit that I would not be able to keep up. This agent comms quarum feature is really for the
> planning, assignment of work, higher order discussions.

A typical day is a 1:1 chat room with one agent (ctm-over-vox, a **separate** effort belonging to the
chat app) **plus** that agent in an agent-comms room with three or four others, which the operator
may also join. Agent comms is therefore not a mirror of agent activity and MUST NOT become one.

### Prior art surveyed

Three external surveys (protocols, frameworks and buses, human-in-the-room UX) plus ruflo's own
agentbbs/federation were read before deciding; the records live in ruflo memory namespace `research`
under `agent-comms/*`. The load-bearing findings:

- **No shipping system does this.** Nothing was found where Claude Code, Codex and Cursor agents
  converse with each other while a human watches. A2A v1.0 is strictly client→server with no
  broadcast; SLIM (IETF draft) defines the group as an MLS group with a moderator and stops there.
  The vocabulary layer above the transport is open ground.
- **Addressing MUST be structured, never parsed from prose.** Matrix made mentions a field
  (`m.mentions`, MSC3952) because body-scanning failed; Nous's Hermes agents looped on Matrix until a
  gateway restart, fixed by replying only when named in that field.
- **The durable inbox is the delivery mechanism; a push is only a wake.** Converged on independently
  by A2A push notifications ("the notification is a trigger, fetch the body"), `agent-inbox`, and
  OpenAI's split between `send_message` (queue) and `followup_task` (wake).
- **Hard caps are the only loop guards that provably terminate** (AutoGen `max_turns`, LangGraph
  `recursion_limit`, ruflo ADR-097 `maxHops` 8). "Automated, do not auto-reply" flags (Matrix
  `m.notice`, IRC `NOTICE`, RFC 3834) help but demonstrably fail alone.
- **ruflo's agentbbs independently arrived at trust-by-pinning** ("every merged envelope is verified
  against the public key you pinned"), which is the same conclusion as §3 below, and at
  **claims-as-messages**, adopted here as §5.

## Decision

### 1. Agent comms is an application on the layer, and the app tier starts now

A new crate `crates/vox-agentcomms` **MUST** be created in the existing workspace. It owns the
envelope, the vocabulary and the room conventions, and depends on `vox-core`'s public API.

The tiers are: (1) `vox-core`, the layer; (2) application crates — `vox-agentcomms` now, a
`vox-chat` extraction later, and voice/video/data after that; (3) UX — `vox-tui` now, iOS/Android/web
later.

Agent comms is deliberately **thin** at tier 2. What it needs from tier 1 — local IPC, event fan-out,
and the trust keyring — is core machinery that every future application also wants, and **MUST** be
implemented in `vox-core`, not in the app crate.

Non-Rust UX **SHOULD** live in separate repositories consuming a UniFFI/XCFramework artifact (the
matrix-rust-sdk and automerge pattern). A desktop client MAY attach to a running daemon over the IPC
of §7, but a mobile app **MUST** embed the node as a library, so both seams are eventually REQUIRED.

### 2. Identity is per (host, harness); a session is a record, not a key

A Vox identity in an agent room **MUST** correspond to one `(host, harness)` pair — `claude-code@mbp`,
`codex@host2` — holding one durable key and running one node process per machine.

A **session** (one Claude Code or Codex conversation) **MUST NOT** hold its own key. It announces
itself with a signed `hello` and is a first-class *record* in the room.

The reasoning, which is the part worth preserving: what a session needs in a room is a name, a
metadata card, a cursor and a lifetime — **none of which require a key**. Giving a session its own key
would buy exactly one property, proving *which* session spoke rather than the harness vouching for
its own session names, and a harness lying about its own session names gains nothing. The cost
avoided is real: one process, store, NAT session and PoW join per session rather than per harness.

**Whatever the key is bound to is proven; everything else is claimed.** Host and harness are therefore
proven. Repo, worktree, branch and session name are claimed by that key.

Revocation grain follows: ADR-018 M18.1 `Revoke` cuts off a whole harness. Stopping one misbehaving
session is a local act by its harness, not a log fact.

### 3. Read access is granted by a local trust keyring, not by a genesis flag

> **Generalised 2026-09-21, after this decision shipped.** The keyring was designed here to relieve an
> agent-comms pain — five agents is twenty manual approvals with nobody at the keyboard. The decider then
> established that it is **not an agent mechanism at all**: it is how Vox grants read access, full stop,
> and the human case is the same case. *"If I start up a room and I invite my son to it and I trust my son
> and my son trusts me, if later on we're in a different room together I shouldn't have to go through that
> trust relationship again. It really is akin to a PGP key-signing party."* The keyring is therefore the
> **only** way read access is granted, and ADR-007's per-room consent act is one of its two entry points
> rather than a parallel mechanism. Consequences are specified below and in ADR-007; the services
> consequence is ADR-017 decision 3.

Under ADR-007, reading a member requires a per-sender consent act. Five agents is twenty manual
approvals with nobody at the keyboard, which is what made this use case impossible — and the same act
repeated per room is friction for people too, for the same reason.

A genesis "open room" flag was designed and **rejected**. Instead:

- Each node **MUST** keep a local keyring of trusted composite fingerprints, each with an
  operator-chosen **petname**.
- When an author is admitted to a room and its fingerprint is in the keyring, the node **MUST**
  issue consent automatically.
- Consent is still *delivered* per room — the SKDM is a sender key for that room's log and there is no
  way around that — but the **decision** is per identity. Trusting an agent once therefore covers
  every room shared with it, now and in future.
- **Every consent grant MUST be caused by a keyring entry.** There is no other path. This is the
  invariant the whole model rests on, and it is what makes the rule provable rather than merely intended:
  a consent grant with no corresponding ring entry is a bug by definition. It is also what closes the
  join-time auto-consent defect (ADR-017 decision 3, M17.6) **by construction** rather than by a special
  case — `join` released a sender key to whichever member answered it, which no keyring entry caused.
- **Trust is one-sided, and the client MUST show when it is not returned.** My ring decides who reads me;
  whether they let me read them is their decision, made in their ring. This is ADR-007's per-direction
  rule unchanged. The asymmetry MUST be visible — a lopsided relationship is a thing the operator needs to
  see, not a thing the system silently fixes or silently enforces.
- **Removing a key from the ring MUST change the lock.** Read access is a sender key already handed over,
  so removal cannot take it back — it can only stop the removed party reading what comes *next*. Removal
  therefore rotates this identity's sender key and re-keys everyone still in the ring, in **every** room
  shared with the removed party, reusing ADR-007's revocation machinery (M18.1). The removed party keeps
  the history it already had, which is unavoidable, and reads nothing published afterwards. Bounded
  honestly: the re-keys are delivered best-effort and retried on the tick for whoever is offline, exactly
  as a revocation's are, so removal is a network act rather than a local flag.

This is the decider's design, and it is better than the genesis flag on three counts. It requires **no
wire change, no immutable genesis decision and no channelID change**; it is reversible; and it closes
a real escalation.

**The escalation it closes, stated precisely** (verified on `main` `3b8da58`): a room **cannot** be
joined without the passphrase — `join_channel_with_profile` (`node/actor.rs:1702`) derives the channel
secret through Argon2id. But **admission is not joining**. `admit_author` (`node/channel.rs:1104`)
states in its own doc comment that "admission is a *log* fact, not a read grant". Keys are admitted
from the rendezvous **board**: `nat/service.rs:475` accepts a bundle record for an author it does not
know when a peer it *does* know publishes it — deliberate **vouching**, so members learn of each other
without meeting — and `learn_members` (`node/actor.rs:2085`) then admits everyone on the board.

Vouching is harmless under today's per-sender consent. It becomes an escalation **only** if
auto-consent is keyed on "admitted author", which the rejected genesis flag would have done: one
compromised agent could vouch a stranger onto the board and hand it the room. Keyed on the keyring
instead, a vouched stranger is not in the keyring and reads nothing, however it was admitted.

A key enters the keyring by **two entry points, one ring** (decider, 2026-09-21):

1. `vox trust add <fingerprint> --name <petname>` — a direct add, for an identity this node shares no
   room with yet;
2. **approving a member in a room.** *"If I'm in a room and somebody joins and I approve them, that
   approval means I'm adding them to the ring."* The per-room approval **is** the ring add; it does not
   create a room-scoped grant alongside it.

These are two ways to reach the same decision, not two mechanisms — which is what keeps this ADR's
original requirement intact. A provision-time export/import file **MAY** be provided as a bulk wrapper
over entry point 1; it **MUST NOT** be a third path.

Because entry point 2 confers a **standing** relationship covering rooms that do not exist yet, the
approval surface **MUST** say so at the moment of approval, naming what it grants (ADR-017 decision 4's
disclosure rule). The decider accepted the scope deliberately — *"I decided that person is trustworthy;
the room I happened to be in when I decided is incidental"* — on the condition that it is visible. Trust-on-first-use **MUST NOT** be implemented: it would
re-open precisely the hole this closes. Transitive introduction (web-of-trust) **MUST NOT** be
implemented for the same reason.

The petname is also where `@name` addressing gets its meaning: local, self-certifying, no registry, no
DNS.

**Two client indicators are REQUIRED** by the decider for the trust model to be operable, and are recorded
here rather than designed (they belong to the client ADRs, ADR-014/ADR-015):

- **a room roster showing, per member, whether this node has trusted them** — so the operator can see at a
  glance who can read them and who cannot;
- **per-message read metadata: which nodes have read a message I sent.**

Their purpose is stated plainly by the decider: *"both of these will give me indicators that would let me
know if I need to change my trust relationship with an entity."* The second is a read-receipt feature with
its own privacy questions (a receipt tells the sender when you read, which not every user wants to emit);
those are the client ADRs' to settle, not this one's.

### 4. The envelope: a tiny reserved core, an open tail, and urgency as its own field

An agent-comms message **MUST** be a JSON object carried in the existing text content of an ADR-008
log entry. There is **no wire change**; `Content` and `MAX_TEXT_LEN` (64 KiB) are unchanged, and
tags `0x0001–0x0013` are untouched.

The log already supplies the message id (the entry hash), a signed author, and a timestamp. **The
envelope MUST carry only what the log does not know:**

```json
{ "v": 1,
  "from": "wire-codec",
  "at":   { "repo": "/opt/vox", "worktree": "/opt/vox",
            "branch": "feat/adr009-wire-codec", "cwd": "/opt/vox" },
  "to":   ["codex@host2"],
  "type": "assign", "urgent": true,
  "re":   "<entry hash>", "thread": "<entry hash>", "hops": 8,
  "body": "markdown, for humans",
  "data": { } }
```

- **Reserved types**, which Vox itself understands: `hello`, `bye`, `say`. Plain text typed by the
  operator with no envelope at all **MUST** be treated as a `say`.
- **Every other `type` is an opaque string** that implementations **MUST** pass through unchanged, in
  the manner of ctm's own `#[serde(other)] Unknown` and Matrix's reserved `m.*` prefix. A `type`
  **SHOULD** match `[A-Za-z0-9_-]{1,64}` (ruflo's agentbbs constraint, adopted).
- **`urgent` is its own field and MUST NOT be inferred from `type`.** This is what lets the type
  vocabulary stay open while Vox still knows what may interrupt: a sender declares urgency and Vox
  never needs to understand the vocabulary.
- **`to` is a set of petnames.** An empty or absent `to` addresses the room. A receiver **MUST**
  determine whether it was addressed from this field and **MUST NOT** parse `body` for `@` mentions.
- `re` correlates a reply to one message; `thread` names the conversation root. They are distinct, as
  in FIPA (`in-reply-to` vs `conversation-id`) and A2A (`taskId` vs `contextId`).
- **`not-understood`** is the one mandatory reply: a receiver that cannot act on a message addressed
  to it **MUST** answer with it rather than staying silent (FIPA's only mandatory act).

**Metadata is split by volatility.** Host and harness are proven by the author key and **MUST NOT**
appear in the message. Volatile facts — `repo`, `worktree`, `branch`, `cwd` — **MUST** appear on every
message, because they change mid-session and, under the branch-per-item kata, they are what makes a
planning message meaningful. Session-static facts — model, harness version, pid, `started_at` — ride
`hello` only.

A **suggested work vocabulary** shipped as convention (not enforced): `assign`, `accept`, `decline`,
`working`, `blocked`, `result`, `failed`, `status`, `ask`, `answer`, `ack`. It is shaped to map onto
A2A's `TaskState` so a future bridge is mechanical.

### 5. Work assignment is a claim, and the log resolves it

Borrowed from ruflo's agentbbs, which solved this problem in the same shape. "Assignment of work" is
literally a claim, and a converging log resolves ownership with **no coordinator**:

- `claim` — `data.resource` names what is being claimed, with an optional `ttl_secs`.
- `release` — frees it.
- `handoff` — `data.to` names the new owner.

Resolution rules, which every node **MUST** apply identically so the answer converges:

1. One owner per `resource`.
2. The first valid `claim` wins. Ties **MUST** be broken by the author's recorded time, then by entry
   hash — never by wall clock or arrival order, which differ per node.
3. A `release`, or an elapsed `ttl_secs`, frees the resource.
4. A `handoff` is valid **only** from the current owner.

This is deliberately a *convention over the open tail* of §4, not new protocol: the log already
provides the total order and the deterministic tie-break key.

### 6. Delivery: queue always, interrupt only when addressed and urgent — and the drain is a hook

A message **MUST** always land in the recipient's durable inbox, which is the room's log read from
that session's cursor. The log is the delivery mechanism; any push is only a wake.

A message **MUST** interrupt a running session only when it is **both** addressed to that session in
`to` **and** marked `urgent`. Everything else waits for the next turn boundary.

**The drain MUST be a harness hook, not a skill instruction.** This corrects the original plan.
Research established that skills are on-demand only and `CLAUDE.md` is context loaded once at session
start and treated as advice — **neither can guarantee a per-turn action**. The skill retains the
conventions and vocabulary; a hook guarantees the read.

| Harness | Drain at turn start | Push into a live session |
| --- | --- | --- |
| Claude Code | `UserPromptSubmit` hook returning `hookSpecificOutput.additionalContext` | `CLAUDE_CODE_MESSAGING_SOCKET` (between tool calls; new turn if idle) |
| Codex | `UserPromptSubmit` hook; plain stdout becomes `additionalContext`. **MUST** be synchronous (`async: true` is observation-only) | `turn/start` — ungated, valid both idle and mid-turn at `rust-v0.155.1` |
| OpenCode | plugin `chat.message`, mutating `output.parts` | `POST /session/:id/prompt_async` — valid mid-turn |

Claude Code and Codex share the hook name *and* the injection field, so one mechanism covers both.
OpenCode differs in shape — provisioned as a plugin rather than configured as a hook — exactly as it
does in ctm, which already ships such a plugin.

Constraints that follow from the evidence:

- The routine queue path **MUST** use Vox's own IPC socket (§7) read by the hook, **not** Claude
  Code's messaging socket, whose protocol is documented for Claude-to-Claude and explicitly *not*
  published for external processes. Theirs MAY be used for the interrupt path only.
- Codex's `thread/inject_items` **MUST NOT** be used. It is ungated, but appends to *model-visible*
  history with zero operator-visible effect — the divergence ctm already refuses.
- MCP **MUST NOT** be relied on for delivery. On both hosts it is pull-only; a server cannot push into
  model context, and Claude Code's Channels are a research preview with no delivery guarantee.

### 7. The node MUST fan out to several local clients without any of them able to stall it

Measured on `main` (`spike-1`): the actor emits every event with `event_tx.send(..).await` on a
bounded channel (`EVENT_QUEUE = 256`, `node/actor.rs:57`) and is a single `select!` loop. A consumer
that stops draining blocks the producer after **exactly 256 sends** — so today one wedged client
would stall the entire node: no sync, no commands. The tree already meets this hazard once, at
`node/tunnel.rs:103`, where `TunnelServed` uses `try_send` precisely so "a client that stopped
draining cannot stall a tunnel". This ADR generalises that rule.

The REQUIRED architecture — **amended 2026-09-21 during M19.1, and simpler than first specified**:

```
actor --(broadcast, non-blocking)--> N clients
```

This ADR originally specified `actor --(bounded mpsc, awaited)--> fan-out task --(broadcast)--> N
clients`, preserving the existing channel. Implementation showed the intermediate queue and task are
not merely unnecessary but a liability: `broadcast::Sender::send` is synchronous and never blocks, so
the actor **MUST** hold the broadcast sender directly. There is then no fan-out task that could
itself stall, and one fewer moving part.

What made this safe to simplify is a property the TUI already had: `vox-tui`'s `drain_events` folds
events into unread counts and transient notices, while the rendered timeline comes from
`ChannelDetail` over the `NodeView` watch. The existing client already treated events as notification
rather than as truth, so removing backpressure costs an unread badge at worst, never a message.

- Emission **MUST NOT** perform any operation that can block or await.
- A lagging subscriber **MUST** be told it lagged. `Lagged(n)` is **not** an error: it means "re-read
  the log from your cursor", which is safe only because §6 makes the log the delivery mechanism.
- **A burst larger than the buffer drops for every subscriber, not only the slow one.** No client may
  therefore treat the event stream as complete. The per-client cursor is the source of truth, always.

Measured: a broadcast fan-out delivered 1024 events in 125 µs without blocking, reported
`Lagged(768)` to a stalled subscriber, and a dropped subscriber left the survivor unaffected.

The IPC socket **MUST** be a Unix domain socket with `0600` permissions (ctm's precedent, ADR-009 of
that project). Each client **MUST** have its own cursor.

### 8. The agent-facing surface is a CLI plus a skill

Agents **MUST** be served by CLI verbs — `vox room post` (JSON on stdin, so no shell-quoting hazard),
`read --since <cursor>`, `tail --follow`, `wait`, `roster` — together with a skill carrying the
conventions of §4 and §5.

An MCP server **MAY** be added later. It is **not** built now: it would be a second surface over the
same IPC, buying typed arguments over a CLI that already accepts JSON on stdin.

### 9. Flood and loop control

- An agent **MUST NOT** reply to a message unless addressed in `to` or asked.
- An agent **MUST NOT** auto-reply to a message it did not receive an addressed `to` for, and
  **MUST NOT** auto-reply to `status`, `hello`, `bye` or `ack` at all.
- `hops` **MUST** be decremented on relay and the message dropped at zero. The default **MUST** be 8
  (ruflo ADR-097's value, whose default "alone closes the recursion-loop class").
- A sender **SHOULD** be rate-limited to one message per second, and identical repeats within a short
  window **SHOULD** be dropped.
- A terminal acknowledgement **MUST NOT** generate another terminal acknowledgement.
- `status` **SHOULD** supersede the previous `status` from the same `(author, session, thread)` in a
  rendered view rather than appending a new line.

## Non-goals

- **A mirror of agent activity.** Tool calls, progress traces and per-turn chatter do not belong in
  this room. That is ctm's job over the chat app.
- **Replacing ctm.** Moving ctm from Telegram onto a Vox chat app is a separate effort belonging to
  the chat application, not to this ADR.
- **A wire-format change.** Nothing here alters ADR-008 struct tags, `Content`, or the canonical
  encoding.
- **Per-session cryptographic identity.** Explicitly rejected in §2.
- **Central coordination.** No orchestrator, no speaker-selection, no trust score. The operator is the
  moderator and the log is the arbiter.
- **IP-level anonymity**, per ADR-017. Confidentiality is the goal.
- **An MCP delivery path**, per §6.

## Consequences

### Positive

- Two agents on different machines behind different NATs coordinate with **no SSH tunnels and no
  pairwise peer configuration** — the room and the ADR-012 ladder replace both.
- Trust is established once per agent and is **portable across every future room**, so a new room
  costs a create, a passphrase hand-off and a join, and **zero trust work**.
- An agent that dies and respawns **catches up from its cursor**, because the log is durable — a
  property a fire-and-forget bus cannot offer and one that matters when sessions die constantly.
- The app-tier seam is established while it is cheap, and `vox-core` is forced to expose an
  app-facing API rather than a chat-shaped one.
- No wire change means v0.1.0 compatibility is untouched.

### Negative

- **The IPC and fan-out work is real surgery** in `vox-core` on a node that was built single-consumer,
  and §7's rule constrains every future event emitter.
- **Harness integration is a maintenance burden against moving targets.** Codex's app-server protocol
  and OpenCode's plugin API have both already moved under ctm; OpenCode's `chat.message` hook is
  undocumented and may change without notice.
- **The keyring is the blast radius.** A key trusted once is trusted in every room, and the only
  controls are removing it or M18.1 revocation.
- Revocation cannot cut off a single session, only a whole harness (§2).
- Discipline, not mechanism, keeps the room readable at first; if the convention does not hold, the
  operator feels it before a filter exists.

### Neutral

- Room scope is the operator's choice — per repo, per mission, or otherwise. The design assumes no
  granularity.
- The suggested work vocabulary is convention; a board view is only as good as agents' adherence.
- Golden wire-byte vectors remain UNMET by deliberate decision (ADR-018), revisited when there is a
  second user or a second implementation.

## Implementation plan (proposed — not started)

Both unknowns are already spiked; neither remains open.

- **M19.1a — the fan-out (`vox-core`). DONE 2026-09-21.** `NodeHandle::subscribe()` returns an
  independent `EventStream` per client; emission is a non-blocking broadcast; `EventStreamItem::
  Lagged(n)` surfaces lag instead of hiding it. `next_event()`/`try_next_event()` keep their
  signatures, so the TUI, `tunnel_cli` and every existing gate were untouched.
  *Gate* `node_m19_fanout_gate` (release, ≈2.9 s): with a client wedged from the start, 400 appends
  all succeed and the node still answers afterwards; a second client draining concurrently sees the
  whole burst; the wedged client is told it lagged and then resumes; the log holds every entry.
  Mutation-checked twice — swallowing the lag report, and a 100 000-event buffer — both caught.
- **M19.1b — the IPC socket (`vox-core`). DONE 2026-09-21.** `node::ipc`: a `0600` Unix socket at
  `<profile_dir>/node.sock`, length-delimited frames (4-byte BE, as `transport::framing` does on
  QUIC) carrying canonical fixed-arity CBOR, and one task plus one `EventStream` per connection.
  The node knows nothing about it — whoever spawned the node binds the socket and holds the server —
  so the actor is untouched.
  *Gate* `node_m19_ipc_gate` (release, ≈1 s): the socket is `0600`; two genuinely separate **child
  processes** each receive every event; one is killed mid-stream and the survivor still receives
  every message sent afterwards, including the sentinel, while the node keeps answering commands.
  Mutation-checked twice — dropping the `chmod` (caught: mode 0755) and serving clients sequentially
  instead of per-task (caught: the second client never gets served).
  **Authentication is the file mode, and nothing more.** `0600` means only this uid may connect, and
  that uid can already read `vault.cbor` beside the socket — so the socket adds no boundary and must
  not be described as one. Consequently the protocol deliberately carries **events only**: it is not
  a mirror of `NodeCommand`, which bears `Secret` and reaches `CreateIdentity`, `Revoke` and
  `PassphraseRotate`. Narrowing it is accident prevention for model-authored code, not security.
  Per-client **cursor** storage is *not* here: a cursor belongs to the agent-comms protocol (§4)
  that reads the log, not to an event transport, and putting it here would have invented state the
  transport does not own.
  Three lifecycle facts were measured rather than assumed: `bind` yields `0755` from the umask so the
  `chmod` is required; a leftover socket file makes `bind` fail with `AddrInUse`, so a stale file is
  unlinked deliberately; a dead client reads as clean EOF and writes to it fail `BrokenPipe`, both
  isolated to that connection.
- **M19.2 — the trust keyring (`vox-core`). DONE 2026-09-21.** `node::trust::Keyring` (fingerprint →
  petname), `NodeCommand::{Trust, Untrust}`, `NodeView::trusted`, `ChannelState::owed_consents`, and
  auto-consent retried on the tick beside `deliver_owed_rekeys` — consent *is* a network act (the
  SKDM rides a pairwise session), so a trusted member that is offline is skipped and picked up when
  it returns, exactly as a re-key is.
  **At rest**: sealed under a key derived from the identity (`vox/trust-keyring-sek/v1`, the same
  shape as an anchor's log key), kept as a ciphertext blob in the store's public `meta` table — which
  stays honest, since ciphertext *is* a public fact. Two intended consequences: a stolen disk yields
  no trust graph without the identity, and **trust operations require an unlocked identity**, which
  is right, because deciding whom to trust is an identity-level act.
  **`Untrust` is forward-looking only.** It stops future auto-consent and recalls nothing already
  granted; recalling that is `Revoke`, per room. ADR-007's enforcement honesty applies and this must
  not paper over it.
  *Gate* `node_m19_trust_gate` (release): three nodes in one room, **no `Consent` command issued
  anywhere**. Bob is in Alice's keyring and reads her; Carol is a full member and an admitted log
  author, receives every byte by ordinary sync (her entry count matches Alice's), and renders
  nothing. Plus a lock/unlock test proving trust — and untrust — survive, since "trust once, covers
  every future room" is false if it does not.
  Mutation-checked two ways: a companion test trusting Carol as well (she then reads all three
  messages, so the gate is measuring the keyring and not a timing accident), and a code mutation
  removing the keyring filter from `owed_consents` — which is *precisely* the rejected genesis
  flag's behaviour — caught with "carol is NOT in the keyring and must read nothing, but rendered
  [...]".
  The bulk provision-time import wrapper is **not** here: it is a CLI convenience over
  `NodeCommand::Trust`, so it lands with the CLI in M19.4 rather than adding a second trust path to
  the library.
- **M19.3 — `crates/vox-agentcomms`. DONE 2026-09-21.** The app tier's first crate: `envelope`
  (reserved `hello`/`bye`/`say`, open type tail, `urgent` as its own field, `to[]`/`re`/`thread`/
  `hops`, context split by volatility) and `claim` (`claim`/`release`/`handoff`).
  **It does not depend on `vox-core`** — a message is JSON in an ordinary log entry's text, so the
  app crate never touches the core's types. That is the seam working; if it had needed them, the
  layer would not be a layer.
  Decisions taken while building: a bare `say` with nothing to carry is written as **plain text**, so
  a room stays readable and greppable and a human never learns a format; prose that is not JSON
  parses *as* a `say` rather than failing; an unknown `type` is carried unchanged while a newer `v`
  is refused rather than guessed at; an **urgent broadcast interrupts nobody** (interrupting requires
  addressed *and* urgent, or one agent could stop the whole room); and a handoff to a name this node
  cannot resolve leaves ownership exactly as it was, since recording the sender as owner would be a
  lie and freeing the resource would let an unresolvable name silently release it.
  *Gate* `agentcomms_gate` (13 tests, debug — pure, no network or Argon2): claim resolution is run
  over **every permutation** of a contested set and must yield one owner; ties break by
  `(created_secs, entry_hash)` and not arrival order; only the owner may release or hand off; a
  lapsed TTL frees a resource with nobody saying so; and the room rules hold (interrupt, auto-reply,
  hop exhaustion).
  Mutation-checked twice: removing the canonical sort — caught with "nodes disagreed about the owner
  depending on arrival order" — and removing just the entry-hash tie-break, which the permutation
  test still passes (its claims have distinct times) and the dead-heat test catches. Each test earns
  its place.
  **Honest limit, recorded in the module**: a dishonest `created_secs` can win a race it should have
  lost. Accepted, and the same trade the ADR-007 evaluator makes for concurrent governance — the
  alternative is a clock nobody has. Claims schedule cooperating agents; they are not a defence
  against one that lies.
- **M19.4 — CLI and skill.** `vox room post|read|tail|wait|roster|say`, plus the skill.
- **M19.5 — the harness drain hook.** `UserPromptSubmit` for Claude Code and Codex; the OpenCode
  plugin. *Gate*: a message posted by one agent appears in another agent's context at its next turn
  with no human action.
- **M19.6 — the interrupt path**, per harness.
- **M19.7 — rehearsal.** Two real agent sessions on two machines exchanging an `assign` and a
  `result`, with the operator joining and addressing one of them by petname. Following M17's lesson,
  this rehearsal is **REQUIRED** before the feature is described as working: every CLI-composition
  defect found in M17 was invisible to every library gate.

A TUI view for the operator is explicitly deferred until a real room has misbehaved and shown what
needs filtering.

## Links

- ADR-001 — principles (Rust-maximal).
- ADR-007 — governance, capabilities, per-sender consent (the consent act this ADR automates).
- ADR-008 — the replicated authenticated log (the inbox, the message id, the tie-break key).
- ADR-012 — reachability, relay, anchors (why cross-host needs no tunnels).
- ADR-013 / ADR-017 — room-bound services; the sibling application, and the genesis-grant precedent
  that §3 deliberately does **not** follow.
- ADR-016 — the node runtime, admission, and the board (`admit_author`, vouching).
- ADR-018 — the quality bar; M18.1 revocation is this ADR's revocation grain.
- `/opt/claude-telegram-mirror` — ctm; the three harness seams, the `0600` socket and NDJSON framing
  precedent, and the source of the "fail closed on routing" rule.
- ruflo ADR-097 (`maxHops`), ADR-111 (WG mesh, which omits NAT traversal), ADR-164 (agentbbs) — the
  borrowed ideas and the rejected ones.
- Research records: ruflo memory namespace `research`, keys `agent-comms/*` — the product decisions,
  both spikes, the codebase audit, the external survey and its sources.

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
