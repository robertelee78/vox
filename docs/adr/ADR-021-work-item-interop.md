# ADR-021: Work-item interop — the contract Vox exposes to an external work tracker

**Status**: **proposed** — 2026-09-23, revised the same day. Design and plan only. **Nothing in this ADR
is built.** Every statement about the tree describes `main` at `0590cdc` (v0.2.4). Every statement about
the contract describes what is to be built.
**Date**: 2026-09-23
**Updated**: 2026-09-23 — the decider's decisions on a review of the first version:
- an **enforced, exact version match** among workers replaces any mixed-version support (§5);
- one claim protocol with **pending handoffs** and **renewal bound to one acquisition** (§4);
- **caller-supplied operation ids**, where a conflict is explicit and monotone (§6);
- self-posts are identified by **author and session** (§7);
- the hands-free guidance says what **replay cannot recover** (§8).

**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: agent-comms, interop, work-tracking, adapter, envelope, claims, versioning, defects

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
- priorities and dependencies;
- durable work state;
- completion policy;
- kanban publishing, GitHub included.

They belong to the tracker. What Vox owes it is the **smallest integration contract** that lets a story
in the tracker be the same unit of work agents assign, claim, discuss and hand off through a Vox room.
That contract has three parts:

1. stable work-item references;
2. compatible event meanings;
3. a way for an adapter to consume the relevant messages.

### The deployment this is optimised for

> I am probably the only operator of this software, and I control the workers. Optimize for a reliable,
> straightforward deployment that I can upgrade together.

**This is the design's governing constraint.** Every worker in a coordinating room is the operator's
own and can be upgraded at once. So correctness is bought by **refusing to coordinate across versions**
rather than by engineering compatibility between them (§5). And the threat model for work coordination
is **cooperating workers that may be buggy**, never adversarial ones: a session name or a version stamp
is a declaration by a trusted harness key, in the sense ADR-020 §2 already uses for "claimed".

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
- **`hello`** (ADR-020 §4), reserved for session-static facts. A worker's Vox version is one.

### Defects found in the shipped surface

These were found while mapping the tree for this ADR, and each was confirmed by reading the code rather
than inferred from ADR text. They are recorded here so they are tracked, whether or not the rest of this
ADR is built. **F1 contradicts a milestone ADR-020 marks DONE**, and is noted in ADR-020 in place.

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
| F11 | **Claim operations carry no version.** | `ClaimOp::from_envelope` (`claim.rs:129-149`) folds `claim`, `release` and `handoff` from any binary, and nothing records which binary posted them. | Workers on different versions fold under different rules and **compute different owners with no signal that they disagree.** Found in review of this ADR's first version. |

F1–F6 and F11 are prerequisites of this contract. F7–F10 are not, and are fixed alongside because they
are small and sit on the same surface.

## Decision

### 1. The boundary

**Vox owns communication, delivery, work-item references and live coordination claims. The tracker
owns work.**

| Concern | Owner |
|---|---|
| What a work item *is*: requirements, acceptance criteria, epic, dependencies, priority | tracker |
| Durable work state and its history; completion policy; publishing | tracker |
| The work-item **reference** in a message | the tracker mints it; Vox carries it opaquely |
| Messages *about* a work item: assign, discuss, report, hand off | Vox room |
| Live ownership among cooperating workers (claims) | Vox, whose fold (§4) decides it; the tracker **records** the result |
| Delivery, durability, confidentiality, and waking a worker | Vox |

Vox **MUST NOT** interpret a work reference beyond carrying it, comparing it byte for byte, and filtering
by it. Vox **MUST NOT** store work state, validate that a reference exists, or compute progress.

**A `result` is a worker's assertion. Completion is the tracker's decision. Releasing ownership means
neither completion nor failure.**

### 2. Stable work-item references

A message about a work item **MUST** carry the reference in `data.work`:

```json
{ "v": 1, "type": "result", "from": "wire-codec",
  "at": { "repo": "/opt/vox", "branch": "fix/handoff-moves-ownership" },
  "body": "handoff now moves ownership; proof attached",
  "data": { "work": "wl:S-7K2QF9M3XA", "attempt": "a-01J9…", "op": "01J9…",
            "vox": "0.3.0", "evidence": [ { "kind": "commit", "ref": "9f3c2e1" } ] } }
```

- **`data.work`** is a string `<scheme>:<id>` matching `[a-z][a-z0-9-]{0,15}:[A-Za-z0-9._~/#-]{1,112}`.
  The scheme names the tracker, so two trackers, or a migration between them, never collide. The id is
  the tracker's, and it **MUST** stay stable for the item's life, through renumbering, re-titling and
  editing of source documents. That stability is the tracker's obligation.
- **`data.attempt`** is OPTIONAL. It names one execution attempt, so a tracker can tell a retry from the
  original. Vox treats it as opaque.
- **`data.op`** is the operation id (§6). **`data.vox`** is the version stamp (§5).
- **`data.evidence`** is OPTIONAL: a list of `{kind, ref, sha256?}`, opaque to Vox. Bytes that must
  move between hosts use ADR-020 §11's file exchange, whose announcement can itself carry `data.work`.

**A claim on a work item uses the reference as its resource**: `data.resource` equals `data.work`. So one
string names the item in ownership, conversation and the tracker.

All of these live in `data`, which needs **no envelope version bump** and keeps ADR-020's reserved core
as small as §4 intended.

### 3. Event meanings

These meanings are **normative for any message that carries `data.work`**. They tell every producer and
consumer what the others mean. Three things are kept apart, as the decider asked:

- **the item's progress** — the tracker's;
- **ownership** — the claim protocol's, §4;
- **one execution attempt.**

| Type | Means | Does **not** mean | Axis |
|---|---|---|---|
| `assign` | the sender asks the addressee (`to`) to take the item | ownership, which only `claim` takes | request |
| `accept` | the addressee agrees and will claim; opens an attempt | ownership, if its `claim` loses | attempt |
| `claim` | take ownership, or complete a pending handoff (§4) | that work has started | ownership |
| `renew` | extend the holder's current acquisition (§4) | a new acquisition | ownership |
| `working` | the owner is actively executing this attempt | measurable progress | attempt |
| `blocked` | the owner cannot proceed; `data.reason` REQUIRED; cleared by the owner's next `working`, `result`, `failed` or `release` | that ownership has lapsed | attempt |
| `status` | a progress note; supersedes the same `(author, from, data.work)`'s previous `status` in any rendering | a state change | attempt |
| `result` | the attempt produced something the sender **asserts** meets the item's criteria; `data.evidence` SHOULD be present | **that the item is complete.** Completion is the tracker's decision. | attempt |
| `failed` | this attempt ended without success, with `data.reason` | **that the item failed or is abandoned.** It may be retried. | attempt |
| `release` | the holder gives up ownership; the attempt ends | **completion, and also not failure.** | ownership |
| `handoff` | the holder relinquishes ownership and reserves the item for a named recipient (§4) | that the recipient accepted | ownership |
| `decline` | with `data.resource`: an eligible recipient refuses a pending handoff, which **frees** the item. Without it: the addressee refuses an `assign`. | that the item is invalid | ownership / request |

- A lapsed lease or a lapsed pending handoff ends ownership **without any message**. A tracker
  therefore **MUST** read ownership from the folded board (§7) and **MUST NOT** reconstruct it from
  claim messages. That keeps the rules in one place.
- `not-understood` remains the mandatory reply (ADR-020 §4) to an addressed work message the receiver
  cannot act on, for example one with a `data.work` scheme it does not know.
- `status` **MUST** be added to `envelope::work` (F7). The skill **MUST** carry this table in place of
  its current bare list.

### 4. The claim protocol

**There is one claim protocol.** It keeps ADR-020 §5's type names (`claim`, `release`, `handoff`) and
its canonical order, `(created_secs, entry_hash)`. It corrects §5 in the ways below, and adds `renew`
and a resource-scoped `decline`. The decider rejected a second vocabulary kept for older binaries: older
binaries are excluded by §5 instead.

**Every claim-protocol operation MUST carry** `data.resource`, a non-empty `from` (the session, F4),
`data.op` (§6) and `data.vox` (§5). An operation missing any of them is **invalid**. It changes nothing,
and the fold reports it as a violation (§7).

**The owner is `(author fingerprint, session)`** (F3). A session is `from`, which is claimed and not
proven, as in ADR-020 §2. The revocation grain remains the harness key.

**A resource is in exactly one of three states:**

- `Free`.
- `Held { owner: (fp, session), acquisition, since, expires }`. `acquisition` is the entry hash of the
  `claim` that created this holding. `expires` is `None` for a claim with no TTL.
- `Pending { from: (fp, session), to_fp, to_session, deadline }`.

**The rules are evaluated in canonical order. Before each operation, lapses are applied first:** a
`Held` whose `expires ≤ op.created_secs` becomes `Free`, and a `Pending` whose `deadline ≤
op.created_secs` becomes `Free`.

1. **`claim`**:
   - on `Free`: → `Held` by `(author, from)`. `acquisition` is this entry. `expires = created_secs +
     ttl_secs` if a TTL was given, otherwise `None`.
   - on `Held`: no effect. The claimant lost.
   - on `Pending`: from an **eligible recipient** (below), → `Held` by `(author, from)`, with this entry
     as the new acquisition and its own TTL. **This completes the handoff.** From anyone else: no
     effect. The claimant lost.
2. **`release`**: on `Held`, only from the exact owner `(fp, session)`, → `Free`. Otherwise no effect.
   A pending handoff cannot be released: the sender has already relinquished, and the recipient uses
   `decline`.
3. **`handoff`**: on `Held`, only from the exact owner, → `Pending`. `data.to_fp` is REQUIRED: the
   recipient's composite fingerprint, resolved by the **sender** from its own keyring at posting time,
   which fixes F1 and F2. `data.to_session` is OPTIONAL, and `data.to` (a petname) is kept for display
   only.
   - `deadline = created_secs + data.ttl_secs`. **`ttl_secs` is REQUIRED on a handoff**, so every pending
     handoff has a finite deadline, including when the original claim had none. The CLI stamps a default
     of 3600 s explicitly, so the fold never has to assume one.
   - **The holding's expiry is replaced, not inherited.** A nearly lapsed claim would otherwise hand the
     recipient no time to act, and a claim without a TTL would give it none to inherit.
4. **`decline`** carrying `data.resource`: on `Pending`, only from an eligible recipient, → `Free`. **It
   does not return the item to the sender**, who may claim it again like anyone.
5. **`renew`**: `data.acquisition` is REQUIRED and names the holding it extends. It takes effect only
   when **all** of the following hold:
   - the resource is `Held` by the exact `(author, from)`;
   - `data.acquisition` equals the current holding's `acquisition`;
   - the holding has a TTL.

   The effect: `expires = renew.created_secs + ttl`, where `ttl` is the acquiring claim's. Otherwise it
   has no effect and is reported as a stale renewal.

   The lapse check runs first, so a renewal that sorts after the holding expired finds the resource
   `Free`, or held under a **different acquisition**. It can therefore neither revive an expired claim
   nor extend a later, unrelated acquisition, even by the same session.

**Eligibility.** For a `Pending` with a `to_session`, the only eligible recipient is **exactly `(to_fp,
to_session)`**. Another session of the same harness can neither accept nor decline it. For a `Pending`
without one, **any session of `to_fp`** is eligible. The first eligible `claim` or `decline` in
canonical order decides, so one session declining frees the item for all of them: the harness declined.

**The known limit is unchanged.** Resolution is deterministic but not causal within one second, as
ADR-020 §5 records. Every node on one version computes the same state. That state need not match the
order in which things happened in wall-clock time.

### 5. Workers must run the same Vox version, enforced

**Mixed-version work coordination is not supported.** Every worker participating in a room's claim
protocol **MUST** run the same Vox version. A worker **MUST** refuse to participate while any
participant's version is mismatched, missing or unknown.

- **The stamp.** Every claim-protocol operation and every work `hello` carries `data.vox`, set by the
  binary to exactly the string `vox --version` reports (`CARGO_PKG_VERSION`). The CLI **MUST** set it
  itself and **MUST** refuse a caller-supplied `vox` key in `--data`, so no worker can misstate it by
  accident.
  - **The comparison is exact string equality.** A stamp that is present but not a valid semantic
    version is *unknown*.
  - Development builds between two tags share a version. That is accepted: the operator upgrades
    together, and a release bumps the version.
- **The fold applies only operations stamped with the folding worker's own version.** Operations from
  any other version, or with no stamp, change nothing and are reported. **An upgrade therefore ends every
  claim made under the previous version**, and workers re-claim. That is the price of upgrading
  together, and it is paid once per upgrade.
- **Who participates.** A worker is a participant if it is still in the room's roster, its latest
  claim-protocol operation or work `hello` is not a `bye`, and **either**:
  - that latest message is within the **participation horizon**: 24 hours, measured against the
    checking worker's clock, the same clock the fold already uses for expiry; **or**
  - it holds or is the target of a resource under this worker's fold.

  Its version is the stamp on that latest message. It is *missing* if that message has no stamp.

  The horizon is what makes the check work in both directions:
  - a newly upgraded worker sees any older worker that is still active **before its own first
    operation**, and refuses to participate at all;
  - a worker that was retired without being upgraded stops blocking the room one horizon after its last
    message, with nobody acting. The pre-ADR history, whose claims carry no stamp, ages out the same
    way.

  Two workers whose clocks disagree may disagree about a participant right at the horizon's edge. That
  can delay or advance a refusal by that clock difference. It cannot change an owner, because ownership
  comes only from stamped operations of the one version.
- **When a worker announces itself.** A session announces itself with a stamped `hello` the first time
  the drain hook runs for that session. It is one message per session, which is what ADR-020 §4 reserves
  `hello` for, and it is not per-turn chatter. So an upgraded worker clears its own mismatch as soon as
  it next works, and nobody has to act.
- **What enforcement means.** When the version table holds any participant that does not match:
  - every claim-protocol verb (`claim`, `renew`, `handoff`, `release`, `decline`) and every `post
    --work` **MUST** refuse before posting and exit with status 3;
  - `vox work`-style starts in the tracker are built on `claim`, so **no claimed work can begin**;
  - the drain hook **MUST** tell the session plainly that coordination is refused and why;
  - `board --json` reports the room as `coordination: refused`, with the table.

  A warning, or a check that is only on the board display, does not satisfy this. The refusal happens in
  the verb that would otherwise have participated.

  Plain conversation (`say`, and posts without `--work`) is **not** refused, so the operator can still
  talk to the room while the problem is fixed.
- **What the refusal says.** It **MUST** name the incompatible worker, its version and the required
  version:

  ```
  vox: work coordination refused in room 7QX2M4KD9A1B
    worker 3F9A0C21B7E4 (codex@host2) session wire-codec runs vox 0.2.9; required 0.3.0
    every worker in a coordinating room must run the same vox version — upgrade it, or remove it
    from the room
  ```

  "Required" is the refusing worker's own version: the rule is equality, and the operator knows which
  side is current. Each worker in a split room refuses symmetrically, naming the others.
- **Why this is sufficient.** Workers on one version fold identically, which is what ADR-020 §5
  requires. Any worker on another version is detected the moment it participates, and every
  implementing worker then stops coordinating until the versions match.
- **The honest limit.** A binary that predates this ADR enforces nothing. Its own fold misreads the
  room, and its operations appear as *missing* stamps, so every current worker refuses. Nothing in the
  room can make an old binary refuse by itself. Upgrading together is the remedy, which is exactly the
  deployment this is optimised for.

### 6. Operation ids: real retries, explicit conflicts

Every work message and every claim-protocol operation carries `data.op`.

- **The caller SHOULD supply the id**, with `--op ID` (`[A-Za-z0-9._-]{8,64}`), and **MUST** reuse it on
  every retry of the same operation. If none is given, the CLI generates one. That is a convenience for
  callers that do not need to recover from a lost response, and it offers no retry safety.
- **Identity.** An operation is identified by `(author fingerprint, op)`, and op ids **MUST** be unique
  per author.
- **Semantic content.** Two entries are the same operation's content when they agree on `type`, sorted
  `to`, `urgent`, `re`, `thread`, `from`, and `data` with the `op` key removed, compared as canonical
  JSON (sorted keys). `body`, `at`, `hops` and `v` are excluded. The body is human prose that a retrying
  model may reword, and `at` is volatile context.
- **A retry** is a later entry with the same identity and the same semantic content. It has no effect,
  and it is reported as `duplicate_of` the first.
- **A conflict** is any two entries with the same identity and different semantic content. **A
  conflict voids the operation: every entry in the group has no effect**, in the claim fold and in the
  adapter contract alike, and every one of them is reported.

  This is the rule that stops a late-arriving, earlier-sorting message from silently replacing an
  operation the tracker has already acted on. Under "first by canonical order wins", that message would
  quietly change the answer. Under voiding, it produces an **explicit conflict event** instead.
  - The void applies whatever order entries arrive in, so every node agrees.
  - **Conflict status is monotone**: an operation can go from ok to conflicted, and never back.
  - A tracker that acted on the first entry learns of the conflict in the stream (§7) and applies its
    own policy. Vox never resolves it by picking a winner.
- **Posting.** `vox room post --op ID` and every claim-protocol verb with `--op`:
  1. look up earlier entries from this identity with that `op`. An identical one means the CLI returns
     its entry hash with exit 0 and **does not post again**. A different one means it refuses with exit 4
     and names the conflict.
  2. Otherwise, post.
  3. **Then re-read** the group. If a conflict exists — for example two concurrent retries with
     different content — exit 4 and report it. **Conflicting content never returns success.**

  The pre-post lookup only saves a duplicate entry. It is not what makes a retry safe. Safety comes from
  (author, op) identity plus the void-on-conflict rule, which hold even when the lookup races.

### 7. What Vox exposes to an adapter

An adapter is a process on a node's host that reads the room and feeds the tracker. It holds its own
(host, harness) identity per ADR-020 §2, e.g. `tracker@mbp`, runs the same Vox version as the workers,
and is trusted like any worker. It sees exactly what its node can decrypt. It needs **four surfaces,
all over the existing control socket, and no new socket request**:

1. **A gapless, resumable stream** (F5, F6):
   `vox room tail ROOM --since CURSOR --json`. This **MUST** deliver every row after `CURSOR`, then every
   row as it lands, **with no gap across a lag or a restart**. Internally:
   - subscribe first, then `Read { since }`;
   - emit the read rows, then the live rows, dropping duplicates by entry hash;
   - on `Lagged`, re-read from the last emitted hash.

   Duplicates across a restart are permitted; **gaps are not**. The adapter owns the cursor and persists
   it after processing, as the drain hook does.
2. **A versioned row schema**: NDJSON, one object per row:

   ```json
   { "schema": "vox.room.row/1", "room": "<b32>", "entry_hash": "<b32>",
     "author": "<fingerprint b32>", "created_secs": 1790000000,
     "text": "<raw>", "envelope": { … } | null, "parse_error": "…" | null,
     "op": { "id": "…", "status": "ok" | "duplicate" | "conflict",
             "group": ["<entry hash>", …] } | null }
   ```

   - Rows are in the node's local timeline order, **which is not the canonical order**, and the schema
     says so. A consumer needing a total order sorts by `(created_secs, entry_hash)`.
   - When a newly landed row turns an operation into a conflict, the stream **MUST** also re-emit every
     earlier row of that group with `status: conflict`. A consumer therefore learns of the change from
     the stream alone.
   - `--work REF` and `--type T` **MAY** filter on the client side.
3. **The folded board**: `vox room board ROOM --json`. It reports:
   - per resource: `state` (`held` or `pending`); `owner_fp`, `owner_session`, `acquisition`,
     `since_secs`, `expires_secs`; or `to_fp`, `to_session`, `deadline_secs`;
   - `coordination` (`ok` or `refused`) with the version table (§5);
   - `violations`: invalid operations, stale renewals, conflicts, and operations from other versions that were ignored;
   - the log position the board reflects.

   The tracker records ownership from this and never reimplements the fold.
4. **Structured posting**: `vox room post ROOM --type T [--work REF] [--attempt A] [--op ID] [--to
   NAME…] [--urgent] [--data JSON] -`, with the body on stdin.
   - It fills `from` and `at` (F4). `from` is `VOX_AGENT_NAME` if set, else the harness session id.
     `at` comes from the git state of the working directory.
   - It stamps `data.vox`, and honours §6.
   - With `--json`, it prints `{entry_hash, op, status}`.

   This is how workers report without hand-writing JSON, and how the tracker posts an `assign`.
   **Raw `vox room post` of a claim-protocol type is refused.** Such an operation would lack the stamp
   and the session that make it valid, and the verbs exist to set them.

**The drain hook suppresses a session's own messages only when both the author fingerprint and the
session match** (F8). A row is skipped only if `author == this node's fingerprint` **and** `from ==
this session`. Another harness using the same session name, or another session on this harness, still
reaches the model. The hook does not filter by work reference: a model should see what its room says to
it.

**Explicitly not exposed:** a new `Request` variant, a server-side filter, a push to the tracker, or any
per-tool-call event. The adapter pulls from its cursor, so a tracker that is down loses nothing that
was posted.

### 8. Hands-free guidance: what replay can and cannot recover (a tracker obligation, not Vox's)

The decider's condition — no ticket maintenance and no manual status repair — is the tracker's to meet.
Vox's part is the durable log and the gapless stream. Two kinds of gap must not be confused:

- **An emitted event the adapter missed** (down, lagging, crashed) is **recoverable**. The room log is
  durable, and the adapter replays from its cursor (§7).
- **A fact never emitted or recorded** is **not recoverable by any replay.** Examples: a blocker a
  worker never reported, an assignment made only in prose to a model, a planning decision that stayed
  in someone's head. Replay finds nothing, because nothing was written.

**Git is authoritative for source and integration facts only**: what changed, on which branch, and
what reached the integration branch. It cannot reconstruct an unreported blocker, an assignment or a
planning decision.

**The tracker and its worker integrations MUST therefore record planning facts through structured
operations at the moment they happen.** That means `assign`, `blocked`, `decline`, `result` and
`failed`, all with `data.work`, emitted by the tracker's own tooling and hooks rather than left to a
model's memory. That responsibility, and the mechanisms that make those operations hard to omit, sit
outside Vox. What Vox guarantees is narrower and complete: **whatever was posted is delivered, in a
form a program can consume, without gaps.**

## Non-goals

- **Vox as the tracker.** It holds no epic, story, priority, dependency, verdict or column, and builds
  no kanban UI.
- **Mixed-version coordination**, or a second claim vocabulary to accommodate older binaries (§5).
- **A wire change.** Every addition is in `data` or in the CLI. The envelope stays at `v: 1`, and
  nothing touches struct tags or `Content`.
- **A socket protocol bump.** Every surface composes `Read`, `Subscribe` and `Post`.
- **Vox validating a reference** against any tracker.
- **Defence against a dishonest worker.** Session names, version stamps and op ids are declarations by
  trusted harness keys (§Context).

## Consequences

### Positive

- The contract is small: a few reserved `data` keys, one claim protocol, a meaning table, and four CLI
  surfaces.
- Every worker on one version computes the same owner, and a worker on another version is refused
  loudly, with a name, rather than quietly disagreeing.
- A retry is safe, and a conflict is never silent, in the fold and in the stream alike.
- F1–F11 are fixed whether or not a tracker is ever built, and F1–F3 made the shipped board wrong.

### Negative

- **Upgrading ends every live claim**, because the new version's fold ignores the old version's
  operations. Workers re-claim, and a tracker sees releases it did not ask for. This is accepted, since
  the operator upgrades together.
- **A stale worker blocks coordination for the whole room** until it is upgraded, removed from the
  room, or has been silent for one participation horizon (24 hours). That is the hard failure the
  decider asked for, and it is loud by design.
- **A conflict voids an operation after a tracker may have acted on it.** The tracker must handle that
  explicitly. The alternative, silent replacement, was rejected.
- **The adapter sees only what its node can decrypt.** A tracker attached to a node missing a trust
  relationship misses that author's messages. This is ADR-020 §3 working as intended.

## Implementation plan

Each milestone is proved per ADR-018 through the shipped `vox` binary, driven as a worker would drive
it, with receipts retained. Each proof names its mutation and must be caught by it, and asserts the
property rather than a proxy. **Nothing is marked DONE without the commit that lands it and the gate
that proves it.**

- **M21.1 — the version gate (F11).** Stamping, the version table and its horizon, the fold applying
  only its own version's operations, refusal in every participating verb and in `post --work`, the hook
  notice, `coordination: refused` on the board, and the exit status 3 message.

  *Proof* `work_version_proof`:
  - **mismatched**: a real mixed room, with a worker on the published **v0.2.1** binary and its own
    node. `update_proof` already fetches releases, so this needs no fixture. v0.2.1 posts a claim with
    no stamp, which is a *missing* version, and the current worker's `claim` exits 3 naming that worker,
    `missing` and the required version.
  - **unknown and different**: a v0.2.1 worker posts the raw JSON a foreign binary would produce, once
    with `"vox": "banana"` and once with `"vox": "0.2.9"`. The current worker refuses and names both.
  - **recovery**: the stale worker is replaced by a current one whose first drain posts a stamped
    `hello`, and coordination resumes **with nobody running a command**.
  - **before first participation**: a current worker that has never posted in the room, joining while
    a different-version worker is active, has its **first** `claim` refused. It never posts.
  - **conversation survives**: plain `post` still works while coordination is refused.

  *Mutations*:
  - skip the check in `claim` alone — the verb begins claimed work, and must be caught;
  - compare versions by major.minor only — `0.2.9` must still be refused;
  - compute the table only from messages stamped with the checker's own version — the
    before-first-participation case must be caught;
  - accept a missing stamp — the v0.2.1 case must be caught.
- **M21.2 — session ownership and the pending handoff (F1, F2, F3).**

  *Proof* `work_handoff_proof`, with two nodes, three sessions, and **different petnames for the
  recipient on each node**:
  - **session ownership**: two sessions on one harness contend, and exactly one is told it holds.
    `release` from the other session has no effect.
  - **acceptance**: Alice hands to Bob's harness untargeted. Both boards show `pending` for Bob's
    fingerprint and name Alice nowhere. A session of Bob claims, and both boards show that session
    holding. Alice's later `release` changes nothing.
  - **targeted**: the handoff names `bob/s2`. `bob/s1`'s `claim` and `decline` both have no effect.
    `bob/s2`'s `claim` completes it.
  - **decline**: an eligible decline frees the item, and it does **not** return to Alice. A fresh
    `claim` by Carol succeeds.
  - **expiry**: the sender's claim had **no TTL**. The handoff's deadline still lapses, and the item is
    `Free`. A recipient's `claim` after the deadline is an ordinary claim on a free item.

  *Mutations*:
  - restore `resolve(.., |_| None)` — "handoff did not move ownership";
  - resolve by the local petname instead of `to_fp` — the two nodes' boards must disagree;
  - inherit the holding's expiry — the no-TTL case never lapses;
  - make a pending item return to the sender on decline.
- **M21.3 — renewal bound to one acquisition.**

  *Proof* `work_renew_proof`:
  - a renewed claim outlives its original TTL, and an unrenewed one lapses;
  - a renewal posted **after** its holding expired does not revive it;
  - a renewal naming a **previous** acquisition, by the same session after a re-claim, does not extend
    the new one, and is reported as stale;
  - a renewal from another session of the same harness has no effect.

  *Mutation*: match a renewal on owner alone, ignoring `acquisition` — the re-claim case must be
  caught.
- **M21.4 — operation ids and conflicts.**

  *Proof* `work_op_proof`:
  - the same `--op` posted twice with the same content yields one entry, with exit 0 both times;
  - forced past the pre-post lookup (two concurrent posts), it yields two entries and exactly **one**
    operation in the fold and in the stream;
  - the same `--op` with a different `data.resource` exits 4, and the fold applies **neither**. The
    stream re-emits the first row as `conflict` after the second lands. The proof delays the
    earlier-sorting entry's arrival at the consumer node until the consumer has already recorded the
    later one.

  *Mutations*:
  - "first by canonical order wins" instead of voiding — the late-arriving case must be caught;
  - remove the post-then-re-read — the concurrent conflict must not exit 0.
- **M21.5 — the adapter stream and the board (F5, F6).** `tail --since --json`, `read --json`, the row
  schema, and `board --json`.

  *Proof* `adapter_stream_proof`:
  - a consumer is killed three times at random points during a 2,000-message burst that exceeds the
    broadcast buffer;
  - after each restart from its own persisted cursor, the union of what it emitted equals the log;
  - no gap, and duplicates only across the kill points;
  - the board JSON equals the owner folded independently from the same rows, across a contested
    claim, a completed handoff and a lapse.

  *Mutation*: subscribe *after* reading. The race window must be caught as a gap.
- **M21.6 — structured posting and self-post filtering (F4, F7, F8).** `post` with `--type`, `--work`,
  `--attempt`, `--op`, `--data` and `--json`; `from` and `at` filled in; `status` added to the
  vocabulary; raw claim-type posts refused; and the drain hook's `(author, session)` suppression.

  *Proof* `drain_self_filter_proof`, run against a live model as in M19.5b:
  - session A on harness H posts. A's next turn does not see its own post.
  - session B on the same harness H, and session "A" on a **different harness** H′, both see it.
  - H′'s post under the name "A" reaches session A on H, because the fingerprints differ.

  *Mutation*: compare `from` only — H′'s message is lost, and must be caught.
- **M21.7 — housekeeping (F9, F10).** The `--since` help text; the index rows for 018–021; the skill
  carries the §3 table.
- **M21.8 — rehearsal against a stub tracker.** A stub tracker, about 100 lines living inside the proof
  and not the product:
  - it mints two references, posts `assign` through `post --op`, and records state from `tail` and
    `board`;
  - two live-model workers do the work, and one is killed mid-attempt.

  *Assertions*:
  - the stub's record of each item's owner, pending handoffs and attempt history matches the log at
    every checkpoint;
  - a `release` is never recorded as completion;
  - a `failed` attempt leaves the item retryable;
  - **the operator runs no command.**

  *Mutation*: `--pure` models, which must turn it red.

## Links

- ADR-008 — the log, its ordering and tie-break key.
- ADR-018 — product proof; the standard the plan is held to.
- ADR-020 — the envelope (§4), the claim protocol this revises (§5), the drain hook (§6), the socket
  (§7), the verbs (§8) and file exchange (§11).

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
