# ADR-021: Work-item interop — the contract Vox exposes to an external work tracker

**Status**: **proposed** — 2026-09-23. Design and plan only. **Nothing in this ADR is built.** Every
statement about the tree describes `main` at `0590cdc` (v0.2.4). Every statement about the contract
describes what is to be built.
**Date**: 2026-09-23
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: agent-comms, interop, work-tracking, adapter, envelope, ipc, defects

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** and **MAY** in this
document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they
appear in all capitals.

## Context

### The requirement, and the boundary the decider drew

The decider wants a kanban and work-management system that turns ADRs into epics and stories, tracks
priorities, dependencies and verified completion, and is **maintained by agents with no administration
by the decider**. The scope is explicit:

> I'm not asking Vox to become the work tracker or derive the entire board from its room history. I want
> a separate, agent-maintained kanban/work-management system that interoperates with Vox.

Consequently the following are **not Vox's**, and this ADR does not design them:

- ADR decomposition;
- epics and stories;
- prioritisation;
- completion and verification policy;
- durable work state;
- board publishing, including to GitHub.

They belong to the tracker. What Vox owes it is the **smallest integration contract** that lets a story
in the tracker be the same unit of work agents assign, claim, discuss and hand off through a Vox room.
That contract has three parts:

1. stable work-item references;
2. compatible event meanings;
3. a way for an adapter to consume the relevant messages.

### What ADR-020 already provides

Most of the contract is already there, and the design reuses it rather than adding beside it:

- **An open envelope** (ADR-020 §4): any `type` passes through unchanged, and `data` is an opaque JSON
  payload. Unknown top-level fields are tolerated but *dropped* on re-serialisation (`envelope.rs`
  derives `Deserialize` without `deny_unknown_fields`). **`data` is the only place an extension survives
  a round trip through an older binary.**
- **A work vocabulary** — `assign`, `accept`, `decline`, `working`, `blocked`, `result`, `failed` — and
  claims (`claim`, `release`, `handoff`) with a deterministic fold. The vocabulary is a convention, and
  its meanings are **stated nowhere precisely enough for a second system to act on them**.
- **A control socket** (`node::ipc`, protocol 5) with `Read { since, limit }` from a cursor and
  `Subscribe` to live events. An out-of-process reader therefore already has the two primitives it
  needs. Only a stable, machine-readable surface over them is missing.
- **An identity model** (ADR-020 §2): one key per (host, harness), and sessions as claimed names. A
  tracker's adapter is just another harness under this model and needs nothing new.

### Defects found in the shipped surface

These were found while mapping the tree for this ADR, and each was confirmed by reading the code rather
than inferred from ADR text. They are recorded here so they are tracked, whether or not the decider
adopts the rest of this ADR. **F1 contradicts a milestone ADR-020 marks DONE**, and is noted in ADR-020
in place.

| # | Defect | Evidence on `0590cdc` | Consequence |
|---|---|---|---|
| F1 | **`vox room handoff` never moves ownership.** | `read_board` calls `claim::resolve` (`room_cli.rs:409`), which is `resolve_with(.., \|_\| None)` (`claim.rs:182-184`). Every recipient is therefore unresolvable, and the §5 rule "an unresolvable name changes nothing" applies. `work_board_proof.rs` never exercises handoff. | ADR-020 M19.9 is DONE with one of its three verbs inert. The `(handed to X, unresolved)` board label cannot print. |
| F2 | **Handoff resolution cannot converge even once wired.** | `resolve_with` maps the recipient petname through the *reading* node's keyring. Petnames are local by design (ADR-020 §3). | Two nodes that named the recipient differently compute different owners. This breaks §5's "every node MUST apply identically". |
| F3 | **Ownership is per node, not per session.** | `Posted.author` is the (host, harness) key, and `claim_resource` compares `owner == client.me()`. | Two sessions on one harness are both told "you hold X". This is the failure claims exist to prevent. |
| F4 | **The CLI never fills `from` or `at`.** | `post_claim_op` uses `Envelope::new`, which leaves both empty (`envelope.rs:162-176`). `vox room post` posts text as given. | ADR-020 §4 says volatile context "MUST appear on every message". No reader can tell which session, repository or branch a message came from. |
| F5 | **No machine-readable output.** | Every `vox room` verb prints text for people. Multi-line text is not escaped in `read`. `created_secs` is never printed. | A program has to scrape output meant for humans, and a message containing a newline corrupts the scrape. |
| F6 | **`tail` cannot resume from a cursor.** | `tail` subscribes only. On `Lagged` it prints "re-read with `vox room read --since`" (`room_cli.rs:320-326`). | A consumer that restarts, or that falls behind, loses messages unless it reimplements read-then-subscribe correctly itself. |
| F7 | **`status` is missing, and §9's supersession is unbuilt.** | `envelope::work` (`:32-55`) lacks `STATUS` although §4 lists it. Nothing supersedes a `status`. | The vocabulary ADR-020 documents is not the one the code ships. |
| F8 | **The drain hook re-injects the session's own posts.** | `agent_hook.rs:262-298` injects every row after the cursor. | Model context is spent on the agent's own words. With F4 unfixed, the hook cannot even tell which rows are its own. |
| F9 | **`--since` help text is wrong.** | `cli.rs:626` says "the full 64 characters". A cursor is `B32_DIGEST_LEN = 52` (`link.rs:63`). | An agent following the help pads or truncates a cursor and gets an error. |
| F10 | **The ADR index is stale.** | `docs/adr/README.md` lists ADR-020 as "proposed — not started". ADR-018 and ADR-019 have no index row. | The index and the ADRs disagree. |

F1–F6 are prerequisites of this contract. F7–F10 are not, and are fixed in the same milestone because
they are small and all sit on the same surface.

## Decision

### 1. The boundary

**Vox carries coordination; the tracker owns work.** Specifically:

| Concern | Owner |
|---|---|
| What a work item *is*: its requirements, acceptance criteria, epic, dependencies, priority, completion | tracker |
| Durable work state and its history | tracker |
| The work-item **reference** in a message | the tracker mints it; Vox carries it opaquely |
| Messages *about* a work item: assign, discuss, report, hand off | Vox room |
| Live ownership among cooperating agents (claims) | Vox room, which folds it (§5); the tracker **records** the result |
| Delivery, durability, confidentiality, and waking an agent | Vox |

Vox **MUST NOT** interpret a work reference beyond carrying and filtering by it. Vox **MUST NOT** store
work state, validate that a reference exists, or compute progress. A tracker **MUST NOT** need Vox to
change when it adds a record kind, a column or a policy of its own.

### 2. Stable work-item references

A message about a work item **MUST** carry the reference in `data.work`:

```json
{ "v": 1, "type": "result", "from": "wire-codec",
  "at": { "repo": "/opt/vox", "branch": "fix/handoff-moves-ownership" },
  "body": "handoff now moves ownership; proof attached",
  "data": { "work": "wl:S-7K2QF9M3XA", "attempt": "a-01J9…", "op": "01J9…",
            "evidence": [ { "kind": "commit", "ref": "9f3c2e1" } ] } }
```

- **`data.work`** is a string `<scheme>:<id>` matching `[a-z][a-z0-9-]{0,15}:[A-Za-z0-9._~/#-]{1,112}`.
  The scheme names the tracker (`wl:`, `gh:robertelee78/vox#42`) so that two trackers, or a migration
  between them, never collide. The id is the tracker's own and **MUST** be stable for the item's life:
  it survives renumbering, re-titling and editing of the source documents. Minting and stability are the
  tracker's obligation. Vox only carries the value, and compares it byte for byte.
- **`data.attempt`** is OPTIONAL. It names one execution attempt, so a tracker can tell a retry from the
  original. It is opaque to Vox.
- **`data.op`** is a client-generated unique id, REQUIRED on anything posted through the new verbs of
  §5. A consumer **MUST** treat a repeated `(author, op)` as one event. The log de-duplicates identical
  entries, but a retry after a crash is a *new* entry with a new timestamp, so it cannot de-duplicate
  one.
- **`data.evidence`** is OPTIONAL: a list of `{kind, ref, sha256?}`, opaque to Vox. When evidence bytes
  must move between hosts, ADR-020 §11's file exchange is the mechanism. Its announcement is itself a
  message that can carry `data.work`.

**A claim on a work item uses the reference as its resource.** `data.resource` equals `data.work`, so
one string identifies the item in ownership, conversation and the tracker. `vox room claim` **MUST**
accept `--work REF` as a synonym for the positional resource and set both fields.

Placing these in `data`, rather than as new envelope fields, is deliberate. It needs **no envelope
version bump**, it round-trips through every shipped binary unchanged, and it keeps ADR-020's reserved
core as small as §4 intended.

### 3. Event meanings

ADR-020 §4 called the vocabulary "shaped to map onto A2A's `TaskState`" and left it at that. A second
system cannot act on a convention whose meanings are unstated, so the meanings below are **normative for
any message that carries `data.work`**. Vox enforces none of them: they tell every producer and consumer
what the others mean.

The table rests on three distinctions the decider asked for:

- **the item's progress** — the tracker's to decide;
- **ownership** — who holds the claim;
- **one execution attempt.**

| Type | Means | Does **not** mean | Axis |
|---|---|---|---|
| `assign` | the sender asks the addressee (`to`) to take the item | that the addressee owns it; ownership is taken by `claim` | request |
| `accept` | the addressee agrees and will claim; opens an attempt | ownership, if its `claim` loses | attempt |
| `decline` | the addressee will not take it, or refuses a handoff, with `data.reason` | that the item is invalid | request |
| `claim` | take ownership (§5 rules) | that work has started | ownership |
| `working` | the owner is actively executing this attempt | progress toward done in any measurable sense | attempt |
| `blocked` | the owner cannot proceed; `data.reason` is REQUIRED; cleared by the owner's next `working`, `result`, `failed` or `release` | that ownership has lapsed | attempt |
| `status` | a progress note; supersedes the same `(author, from, data.work)`'s previous `status` in any rendering | a state change | attempt |
| `result` | the attempt produced something the sender asserts meets the item's criteria; `data.evidence` SHOULD be present | **that the item is done.** Done is the tracker's verdict, not the agent's assertion. | attempt |
| `failed` | this attempt ended without success, with `data.reason` | **that the item failed or is abandoned.** The item is unchanged and may be retried. | attempt |
| `release` | the owner gives up ownership | **that the work is done.** It is also not a failure. The attempt ends; the item returns to whoever tracks it. | ownership |
| `handoff` | the owner transfers ownership to `data.to_fp` (§4) | that the recipient accepted; it MAY `decline` | ownership |

Two consequences follow. Neither is new mechanism:

- **A lapsed claim TTL ends ownership and ends the attempt.** A consumer sees it as the absence of the
  owner on the board (§5), not as a message. A tracker therefore **MUST** read ownership from the
  folded board and **MUST NOT** reconstruct it from claim messages. That rule is what keeps the tie-break
  in one place.
- **`not-understood` remains the mandatory reply** (§4) to an addressed work message the receiver cannot
  act on, for example one with a `data.work` scheme it does not know.

`status` **MUST** be added to `envelope::work` (F7). The skill **MUST** carry this table in place of the
current bare list.

### 4. Claims: per session, handed off by fingerprint

Three changes make ownership trustworthy enough for a tracker to record. None changes §5's tie-break or
its convergence.

1. **The owner is `(author, session)`** (F3). A `claim` carries the session in `from`. Session names
   are claimed, not proven, as in ADR-020 §2. Revocation grain stays the harness key.
2. **A handoff MUST carry `data.to_fp`**, the recipient's composite fingerprint. The **sender** resolves
   it from its own keyring at posting time. `data.to_session` is OPTIONAL. The fold transfers
   ownership on `to_fp` alone, so every node computes the same owner (F1, F2). `data.to` stays for
   display. A handoff without `to_fp` changes nothing, as today, and is displayed as unresolved.
3. **`renew`**, from the owner only, extends a claim by its original `ttl_secs` from the renew's own
   timestamp. Without it, a long piece of work needs either an unbounded TTL, where a dead agent holds
   the item forever, or a release-and-reclaim, which briefly frees it to a competitor.

### 5. What Vox exposes to an adapter

An adapter is a process on a node's host that reads the room and feeds the tracker. It holds its own
(host, harness) identity per ADR-020 §2, e.g. `tracker@mbp`, and is trusted like any agent. It sees
exactly what that node can decrypt, and nothing more. It needs **four surfaces, all over the existing
control socket and none a new socket request**:

1. **A gapless, resumable stream** (F5, F6):
   `vox room tail ROOM --since CURSOR --json`. This **MUST** deliver every row after `CURSOR`, then every
   row as it lands, **with no gap across a lag or a restart**. Internally: subscribe first, then `Read {
   since }`, then emit the read rows followed by the live rows, dropping any duplicates by entry hash. On
   `Lagged`, re-read from the last emitted hash. **Duplicates across a restart are permitted; gaps are
   not.** Consumers de-duplicate by `entry_hash`. The cursor belongs to the adapter, which persists it
   after processing, exactly as the drain hook already does.
2. **A stable row schema** — one NDJSON object per row, versioned:

   ```json
   { "schema": "vox.room.row/1", "room": "<b32>", "entry_hash": "<b32>",
     "author": "<fingerprint b32>", "created_secs": 1790000000,
     "text": "<raw>", "envelope": { … } | null, "parse_error": "…" | null }
   ```

   Rows are in the node's local timeline order. **That is not the canonical order**, and the schema says
   so. A consumer needing a total order sorts by `(created_secs, entry_hash)`, as §5 does. `--work REF`
   and `--type T` **MAY** filter on the client side, as a convenience that does not change the schema.
3. **Folded ownership**: `vox room board ROOM --json`. It emits `{resource, owner_fp, owner_session,
   since_secs, expires_secs, handoff_pending}` per held resource, plus the log position it reflects. The
   tracker records ownership from this, per §3. It never reimplements the fold.
4. **Structured posting**: `vox room post ROOM --type T [--work REF] [--attempt A] [--to NAME…] [--urgent]
   [--data JSON] -` with body on stdin. It fills `from` and `at` from the environment (F4): `VOX_AGENT_NAME`
   and the git state of the working directory. It mints `data.op`, and prints `{entry_hash, op}` with
   `--json`. This is how agents report without hand-writing JSON, and how the tracker posts an
   `assign` into the room.

**The drain hook is unchanged in purpose and fixed in two respects**: it skips rows whose `from` is the
draining session (F8), and it keeps every other row. It does not filter by work reference. Filtering is
the tracker's business, and a model should see what its room says to it.

**Explicitly not exposed:** a new `Request` variant, a server-side filter, a push to the tracker, or any
per-tool-call event. The adapter pulls from its cursor. So a tracker that is down loses nothing: it
resumes from its cursor when it returns, which is the durable-inbox rule of ADR-020 §6 applied to a
program instead of a model.

### 6. How agents stay hands-free (guidance for the tracker, not a Vox obligation)

The decider's condition — no administration — is the tracker's to meet. Vox's part is to make the
events it relies on unforgettable. The combination that works with the surfaces above:

- **Binding without ceremony.** The tracker mints references. Its extraction job, a model reading ADRs,
  posts nothing to the room. When an item is assigned, the `assign` carries `data.work`. The tracker's
  own `SessionStart` or `UserPromptSubmit` hook, installed beside `vox agent hook`, binds the session's
  branch to the item. Every later Vox post from that session carries the reference automatically:
  `vox room post` reads a `VOX_WORK` environment value, or a binding file the tracker wrote.
- **Liveness without chatter.** `renew` runs from a hook, at most once per half-TTL. It is never a
  per-turn message.
- **Truth from git, not from reports.** The tracker's integration watcher, not a Vox message, observes
  merges and runs verification. Vox messages are the *intent and conversation* around the work, and are
  treated as hints. The tracker reconciles against git and its verifier, so a missed or late Vox event
  never corrupts its state.

The earlier draft of this ADR worked those tracker-side designs out: derived columns, verdicts per
acceptance revision, source-anchored extraction validated by a non-model check, rank with explanation,
and a one-way, level-triggered GitHub projection. They now belong in the tracker's own design record,
and should be carried there. They are not repeated here, because they are not Vox's.

## Non-goals

- **Vox as the tracker.** It holds no epic, story, priority, dependency, verdict or column.
- **A wire change.** Every addition is in `data` or in the CLI. The envelope stays at `v: 1`, and
  nothing touches struct tags or `Content`.
- **A socket protocol bump.** Every surface above composes `Read`, `Subscribe` and `Post`, which already
  exist.
- **Vox validating a reference** against any tracker.
- **Board publishing, GitHub included.**

## Consequences

### Positive

- The contract is small enough to hold in the head: one reserved `data` key, a meaning table, and four
  CLI surfaces.
- A tracker can be replaced, or run in parallel, without a Vox change. The scheme prefix keeps their
  references apart.
- The defects F1–F10 are fixed whether or not a tracker ever exists, and F1–F3 made the shipped work
  board wrong today.

### Negative

- **The meanings in §3 are a convention.** An agent that posts `release` when it means `result` misleads
  a tracker. The tracker's defence is reconciliation against git and its verifier, not trust in the
  message.
- **The adapter sees only what its node can decrypt.** A tracker attached to a node that is missing a
  trust relationship will silently miss that author's messages. This is ADR-020 §3's model working as
  intended. The roster indicator ADR-020 requires is what makes it visible.

## Implementation plan

Each milestone is proved per ADR-018 through the shipped `vox` binary. Each proof is mutation-checked,
names its mutation, and asserts the property rather than a proxy. Nothing is marked DONE without the
commit that lands it.

- **M21.1 — ownership that is true (F1, F2, F3, `renew`).**
  *Gate* `work_handoff_proof`:
  - two nodes on which the recipient has **different petnames**; Alice hands to Bob; both boards show
    Bob; Bob's `claim` reports he holds it; Alice's later `release` changes nothing;
  - two sessions on one harness contend, and exactly one is told it holds;
  - a renewed claim outlives its original TTL; an unrenewed one lapses.

  *Mutations*, each of which must be caught:
  - restore `resolve(.., |_| None)` — "handoff did not move ownership";
  - resolve `to` by the local petname instead of `to_fp` — the boards disagree;
  - compare the owner by author only — both sessions are told they hold it.
- **M21.2 — the adapter stream (F5, F6).** `tail --since --json`, `read --json`, and the row schema.
  *Gate* `adapter_stream_proof`:
  - a consumer process is killed three times at random points during a 2,000-message burst that exceeds
    the broadcast buffer;
  - after restarting from its own persisted cursor, the union of what it emitted equals the log exactly;
  - no gap, and duplicates only across the kill points.

  *Mutation*: subscribe *after* reading. The race window must be caught as a gap.
- **M21.3 — structured posting and the envelope (F4, F7, F8).** `post --type --work --attempt --data
  --json`, `from` and `at` filled in, `data.op` minted, `status` added, and the drain hook skipping the
  session's own rows.
  *Gate*: an agent session posts with `--work`, and a second process reads it back with `from`, `at` and
  `op` populated. A retried post with the same `op` is reported once by a consumer that honours §2.
  *Mutation*: stop filling `at`, which must be caught.
- **M21.4 — `board --json` and the meaning table in the skill.**
  *Gate*: the proof's board JSON equals the owner folded independently from the same rows, across a
  contested claim, a handoff and a lapse.
- **M21.5 — housekeeping (F9, F10).** The `--since` help text, and the index rows for 018–021.
- **M21.6 — rehearsal against a stub tracker.** A stub tracker is a 100-line process that mints two
  references, posts `assign` through `post`, and records state from `tail` and `board`. It lives in the
  proof, not in the product. Two live-model agents do the work, and one is killed mid-attempt.
  *Assertions*:
  - the stub's record of each item's owner and attempt history matches the log at every checkpoint;
  - a `release` never reads as done;
  - a `failed` attempt leaves the item retryable;
  - **the operator runs no command.**

  *Mutation*: `--pure` models, which must turn it red.

## Links

- ADR-008 — the log, its ordering and tie-break key.
- ADR-018 — product proof; the standard the plan is held to.
- ADR-020 — the envelope (§4), the claim fold (§5), the drain hook (§6), the socket (§7), the verbs (§8)
  and file exchange (§11), all extended here without a wire change.

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
