# ADR-021: Work-item interop — the contract Vox exposes to an external work tracker

**Status**: **implemented on `feat/adr021-work-interop` (PR #14), not yet merged to `main`** —
2026-09-24, M21.1–M21.8, each proved through the shipped `vox` binary and mutation-checked; the plan below
names the proof, its mutations and the commit for each. **M21.9 and M21.10 are decided (2026-09-24) and
not built.** Vox holds no work state: an external tracker owns it. Open defects found while building this
sit outside its boundary and are recorded rather than accepted — F12 in `vox-core` key distribution (half
fixed in PR #20), F15 in the daemon's interrupt path (fix in PR #16) and F17, OpenCode delivery (deferred
by the decider); F14 is retired. Statements about the tree before this change describe `main` at `96c47ed`
(v0.2.7).
**Date**: 2026-09-23
**Updated**: 2026-09-24 — implemented; see the revision history below.

Revision history:

- 2026-09-23 — the decider's decisions on a review of the first version: an **enforced, exact version
  match** among workers replaces any mixed-version support (§5); one claim protocol with **pending
  handoffs** and **renewal bound to one acquisition** (§4); **caller-supplied operation ids**, where a
  conflict is explicit and monotone (§6); self-posts are identified by **author and session** (§7); the
  hands-free guidance says what **replay cannot recover** (§8).
- 2026-09-24 — tracker vocabulary and ownership were clarified without changing the wire format: Vox
  observations remain optional inputs to a client-independent external tracker.
- 2026-09-24 — **implemented**, with three amendments forced by the tree and each recorded in place: a
  handoff's recipient is resolved against the room roster, not the keyring (§4); a participating verb
  announces before it checks, and a worker excludes itself from the version table (§5); and `from` is the
  session id, never `VOX_AGENT_NAME` (§7). Implementation also found F13 — `tail` had never delivered
  another member's message — and fixed it, and found F12, F14 and F15, which are open.
- 2026-09-24 — the decider's decisions on fitting the work-accountability tracker: `data.work`'s id
  **admits `:`**, and the shape is **enforced** by the CLI (F16, found then); `data.attempt` **defaults to
  the holder's claim acquisition** (§3). The adapter from `vox room tail --json` to that tracker belongs
  in the tracker's repository, not in Vox.
- 2026-09-24 — at the tracker's request: **a `failed` ends the attempt it names, and the holder's next
  post begins a new one** named by that `failed` entry (§3), so every attempt is bounded; and the
  adapter's **read cycle** over `board.position` and the stream is documented (§7). No wire change.
- 2026-09-24 — the decider's correction for the tracker's model: **a claim establishes ownership only;
  an attempt becomes active only on the holder's `working`**, whose entry is the attempt-start evidence;
  `failed` seeds a retry's id but no retry exists until the next `working`; a `result` with no observed
  attempt-start stays an assertion (§2, §3). The seeded default id is unchanged on the wire.
  `tracker_rehearsal_proof` asserts claim-leaves-Ready, working-enters-Executing, failed-returns-Ready,
  retry-only-on-working and blocked-is-Health-only through live models, and passed (227 s); **the mutation
  check of these new checkpoints is pending** — its first runs were uninformative (the live-model warm-up
  timed out before any checkpoint), not survivors.
- 2026-09-24 — the decider's answers on ideas from a review of Orca: **M21.9** (the drain says when a
  claim was lost) and **M21.10** (a `result` warns about unread addressed messages) are decided and not
  built; grouped addresses (`@claude`, `@idle`) are **declined** — `to` stays explicit names. The status
  now says where the implementation lives, so the text is true on `main` before PR #14 merges.

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
- stable work identity, priorities, rank and dependencies;
- durable Work phase, Health and Source freshness;
- attempts, attempt outcomes, acceptance verdicts and release/delivery verdicts;
- kanban publishing and GitHub projection.

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

**Re-verified 2026-09-24 against `main` at `96c47ed` (v0.2.7)**, before any of this ADR was built: all
eleven still held. v0.2.7 changed the claim sort key from seconds to milliseconds and nothing else in
these paths — `read_board` still folded with `claim::resolve`, whose resolver resolves nobody (F1–F2);
the owner check was still `own.owner == client.me()` (F3); `post_claim_op` still built `Envelope::new`
(F4); no verb had `--json` (F5); `tail` still subscribed only (F6); `envelope::work` still had no
`STATUS` (F7); the drain hook compared neither author nor session (F8); the `--since` help still said 64
characters (F9); the index still said ADR-020 was "not started" (F10); and no claim carried a version
(F11). **Each is closed by this ADR's implementation**, milestone by milestone below.

**Found while implementing, 2026-09-24.** Four more, each reproduced rather than inferred except where
it says so. Two are in `vox-core` and outside this ADR's boundary; they are recorded as **open
defects**, not accepted gaps, because each is a thing a user meets.

| # | Defect | Evidence | State |
|---|---|---|---|
| F12 | **In a room of three, the two members who joined cannot read each other.** | Three in-process nodes on loopback, no anchor: alice creates, bob and carol join, all six `Trust` edges applied; after 60 s, `bob never received the sender key of ["carol"]`. Creator↔joiner keys arrive. `node_m19_untrust_lock_gate` stays green only because none of its joiners reads another joiner. It looks like the gap the ADR index already lists — "re-keying for a member first met off the join path" — but that is not confirmed. | **Open** (`vox-core` key distribution). The ADR-021 proofs therefore run on two nodes with several sessions each, and say why. Remove this entry when a three-member room in which each joiner reads the other passes through the real binaries. |
| F13 | **`vox room tail` never showed another member's message.** | The node emits `NewEntry` only for its own appends; a synced entry is announced as `Synced`, which carries no row, and `tail` listened only for `NewEntry`. Reproduced: bob's `read` count rose while his `tail` printed nothing, in plain mode as well as `--json`. | **Fixed here** (§7 amendment); `adapter_stream_proof` asserts rows synced from another node reach a *live* consumer, and turns red against the old behaviour. |
| F14 | **A rate limit reaches the user as `Failed(Internal)`.** A member who posts more than 1,000 entries in an hour is refused, correctly, by ADR-008's per-author quota (`log/quota.rs`, `DEFAULT_MAX_ENTRIES_PER_HOUR = 1000` over a sliding `RATE_WINDOW_SECS = 3600`) — but `append_text` replaces `Quota(RateExceeded)` with `Error::Profile("authored entry failed the acceptance predicate")` (`channel.rs`), which surfaces as `vox: Failed(Internal)`. A person or agent cannot tell it is rate-limited, or when it may post again. | Reproduced through the real binary by the `vox` session: one member alone in a room, 1,010 `vox room post` calls — posts 0–999 succeed and every later one fails `Failed(Internal)`, identically on v0.2.6 and v0.2.7. Root cause measured by that session with an instrumented build: rotation at the 1,000th message **succeeds** (`rotate_sender: Ok(1)`); every refusal is `dag.accept … Quota(RateExceeded)`. The refusal is **not permanent** — the window slides. My own two-node reproduction first failed at index 999, most likely one earlier non-content entry counted in the same window. (An earlier version of this entry blamed rotation; that was wrong, and it is corrected here.) | **Retired 2026-09-24.** The decider accepted PRD-001 R3 — the per-author rate quota is **removed** — so there is no refusal left to report; the readable-refusal fix (#15) was closed unmerged. (It had been proved: `quota_refusal_proof`, red against the discarded error.) Before that decision, whether 1,000 entries/hour/author was the right default for agent rooms was a **decider question**, not a defect: it is tunable per channel (`QuotaPolicy`), and other members enforce it too, dropping over-quota entries on receipt. `adapter_stream_proof` keeps each member under 1,000 an hour and says why. Remove this entry when a member who exceeds the quota is told, through the real binary, that it is rate-limited and when it clears. |
| F15 | **The daemon's interrupt path sees only this node's own posts.** | Found by reading, then **reproduced through the real `vox daemon`** (`remote_interrupt_proof`: an urgent message from another node reached bob's node and woke nobody — `received []`): `vox daemon` wakes a session on `NodeEvent::NewEntry` (`app.rs`), which by F13's evidence is emitted only for local appends, so an urgent message addressed to a session from *another* node would never interrupt it. `interrupt_proof` calls the wake decision directly and never runs that loop, so nothing would catch it. | **Open; fix proposed in #16** (the daemon sweeps on `Synced`/`SenderKeyReceived`/`Lagged`/a tick; `remote_interrupt_proof` green, red against the shipped loop). Remove when that lands: an urgent, addressed message posted on one node interrupts a session registered on another, through `vox daemon`. |
| F16 | **`data.work`'s shape was specified and never checked, and one spelling skipped the version gate.** | Found reading `post_cmd` against the work-accountability tracker's key format: the CLI refused only an empty `--work`, so any string rode as a reference; and a post that set the reference through `--data '{"work":…}'` instead of `--work` skipped the version gate, which was keyed on the flag rather than on the message. `claim --work` checked nothing either. | **Fixed here**: the reference is checked where it lands in `data`, for every verb, and the gate follows the message (§3). `work_ref_proof` refuses seven malformed references through each of the three spellings with nothing posted, and turns red against each of the removed checks (six mutants, all caught). The gate half — a `--data` reference now passes the version gate — follows by construction (the gate reads the checked reference) and is **not separately proved**; `work_version_proof` drives the gate through `--work` only. |
| F17 | **An OpenCode session opened by hand can never be interrupted.** | Measured 2026-09-24 against OpenCode 1.18.32, a plain TUI in tmux with a probe plugin: the plugin is handed `serverUrl=http://localhost:4096/` but **nothing listens** (no TCP listener; a request fails), and `OPENCODE_SERVER_URL` is **unset**. With `--port 47123` the TUI does listen and the plugin is handed that URL, but the variable is still unset. `vox agent hook` registers a session as OpenCode — and so wakeable — only from `OPENCODE_SERVER_URL` (`wake.rs`), so every OpenCode session registers as `unknown` and an urgent message waits for the next turn. ADR-020 M19.6 is marked DONE for OpenCode, but no test ever posts to `prompt_async` or sets the variable: the gate proved the wake *decision*, not the delivery. | **Open; deferred by the decider 2026-09-24.** Researched and measured the same day (OpenCode 1.18.32, a mock model, no paid turns): the TUI talks to its server in-process and starts a listener only with `--port`, `--hostname` or `--mdns`; `4096` is a placeholder. A plugin's in-process client works once init is over — `promptAsync` from a plain TUI returned 204 and showed on screen. `prompt_async` during a turn is **not** rejected: it is picked up at the next step boundary (after the running tool), shown as QUEUED, exactly as typing while busy. Aborting orphans a queued prompt, so an interrupt must not abort first. `--port` exposes an unauthenticated server whose CORS admits any localhost origin. The candidates are a plugin-owned private socket relayed through the in-process client (ctm's shape), `--port` HTTP, or both; the decider has not chosen. Remove when an urgent, addressed message interrupts a plain, hand-opened `opencode` through `vox daemon` and the real binary. |

## Decision

### 1. The boundary

**Vox owns communication, delivery and live coordination claims. The tracker owns work and mints the
references that Vox carries opaquely.**

| Concern | Owner |
|---|---|
| What a work item *is*: requirements, acceptance criteria, epic, stable identity, dependencies, priority and rank | tracker |
| Work phase, Health, Source freshness and their history | tracker |
| Attempts and attempt outcomes recorded from observations | tracker |
| Acceptance and release/delivery verdicts; publishing and GitHub projection | tracker |
| The work-item **reference** in a message | the tracker mints it; Vox carries it opaquely |
| Messages *about* a work item: assign, discuss, report, hand off | Vox room |
| Live ownership among cooperating workers (claims) | Vox, whose fold (§4) decides it; the tracker **records** the result |
| Delivery, durability, confidentiality, and waking a worker | Vox |

Vox **MUST NOT** interpret a work reference beyond carrying it, comparing it byte for byte, and filtering
by it. Vox **MUST NOT** store work state, validate that a reference exists, or compute progress.

The tracker **MUST** work without Vox and without a particular agent client. A Vox adapter and client
hooks are optional integrations, not tracker prerequisites.

The canonical Work phases are **Backlog, Designing, Ready, Executing, Acceptance, Release ready and
Done**. Health is independently **On track, At risk or Blocked**; Blocked is never a Work phase or a
board column. Source freshness is independently **Current or Reconciliation needed**. Priority, rank,
ownership, attempts and attempt outcomes are also independent facts.

Every Vox event is an observation. **Acceptance, Release ready and Done are tracker verdicts.** A claim,
branch, pull request or file overlap, green CI, merge or worker exit does not by itself establish a Work
phase. Releasing ownership means neither Done nor failure.

### 2. Stable work-item references

A message about a work item **MUST** carry the reference in `data.work`:

```json
{ "v": 1, "type": "result", "from": "wire-codec",
  "at": { "repo": "/opt/vox", "branch": "fix/handoff-moves-ownership" },
  "body": "handoff now moves ownership; proof attached",
  "data": { "work": "wl:S-7K2QF9M3XA", "attempt": "a-01J9…", "op": "01J9…",
            "vox": "0.3.0", "evidence": [ { "kind": "commit", "ref": "9f3c2e1" } ] } }
```

- **`data.work`** is a string `<scheme>:<id>` matching `[a-z][a-z0-9-]{0,15}:[A-Za-z0-9._~/#:-]{1,112}`.
  The scheme names the tracker, so two trackers, or a migration between them, never collide; it is
  everything before the **first** colon, and the id **MAY** itself contain `:`, so a tracker whose keys are
  colon-separated carries them unchanged — the work-accountability tracker's
  `OWNER/REPO:SOURCE:ITEM` rides as, for example, `gwa:robertelee78/vox:adr-021:m21.3`. The id is the
  tracker's, and it **MUST** stay stable for the item's life, through renumbering, re-titling and editing
  of source documents. That stability is the tracker's obligation. **The CLI refuses a reference of any
  other shape before posting**, whichever flag carried it — `--work`, `--data` or `claim --work` (F16).
  Vox checks the shape only; it never interprets the id or looks it up.
- **`data.attempt`** is the attempt's **correlation id**, so a tracker can tell a retry from the original.
  Vox treats it as opaque. **When the caller names none, a work-bound post from the session that holds the
  claim on that item carries a default id**, seeded from the log alone: the hash of the holder's claim
  (its acquisition, as `board --json` shows it), or of the holder's own latest `failed` for the item since
  that claim, whichever is later in canonical order. A `failed` whose operation is void (§6) seeds
  nothing; a retried `failed` is its first entry. A post from a session that does not hold the claim
  carries no id unless it names one; an explicit `--attempt` always wins. A retried `--op` keeps the id
  its first post carried. (`work_ref_proof` proves the seeding against five mutants; the two exclusions
  are by reading only — no proof yet posts a voided or duplicated `failed`.)

  **An id is not an attempt.** Seeding names the attempt that *would* run; it starts nothing. The attempt
  lifecycle is §3's, and it is the same whether the id was seeded or named:
  - a `claim` establishes **ownership only**; `claim`, `renew`, `accept`, `blocked` and `status` never
    start an attempt;
  - **an attempt becomes active only when the holder posts `working` for that item**, and its
    attempt-start evidence is **that `working` entry's hash and timestamp**;
  - `failed` ends the named attempt; the id it seeds belongs to a retry that **does not exist until a
    later `working`**;
  - `release`, a lapse and a handoff end an **active** attempt, and do nothing to attempt state when
    execution never started;
  - a `result` with no corresponding attempt-start observation remains an assertion and **MUST NOT**
    advance a tracker's phase.

  (Decided 2026-09-24, in three steps the same day: first "the claim is the attempt"; then, at the
  work-accountability tracker's request, "a `failed` ends the attempt and the retry is a new one"; then
  the decider's correction for that tracker's model — **a claim is ownership, and only `working` starts
  an attempt**. The wire behaviour is unchanged by the last step: the default id is still seeded as
  above.)
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
| `accept` | the addressee agrees and intends to claim and open an attempt | ownership or that an attempt actually started | request / attempt intent |
| `claim` | take ownership, or complete a pending handoff (§4) | that work has started, that an attempt is active, or that the item is Executing | ownership |
| `renew` | extend the holder's current acquisition (§4) | a new acquisition | ownership |
| `working` | the owner reports active execution of this attempt. **The attempt becomes active here**, and this entry's hash and timestamp are its start evidence; a later `working` with the same id continues it | a Work phase transition by itself; the tracker decides whether this attempt-start is sufficient to record Executing | attempt start / observation |
| `blocked` | the owner reports that it cannot proceed; `data.reason` REQUIRED; cleared by the owner's next `working`, `result`, `failed` or `release` | a Work phase transition or that ownership has lapsed; the tracker decides durable Health and leaves Work phase unchanged | attempt / health observation |
| `status` | a progress note; supersedes the same `(author, from, data.work)`'s previous `status` in any rendering | a state change | attempt |
| `result` | the attempt produced something the sender **asserts** meets the item's criteria; it SHOULD name an immutable candidate in `data.evidence`, such as a commit rather than a branch | an acceptance verdict, Release ready or Done. The tracker may use a valid candidate to enter Acceptance **only for an attempt whose `working` it observed**; without one it stays an assertion | attempt observation |
| `failed` | this attempt ended without success, with `data.reason` | **that the item failed or is abandoned.** It may be retried; the retry begins at the next `working`, not here | attempt end |
| `release` | the holder gives up ownership; an **active** attempt ends | **Done, and also not failure**; nothing about attempts when none was active | ownership |
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
its canonical order, `(created_millis, entry_hash)` — milliseconds since v0.2.7 (ADR-020 §5, M19.9).
It corrects §5 in the ways below, and adds `renew`
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
`Held` whose `expires ≤ op.created_millis` becomes `Free`, and a `Pending` whose `deadline ≤
op.created_millis` becomes `Free`. Every lease and deadline is kept in milliseconds (`ttl_secs × 1000`);
nothing orders by seconds.

1. **`claim`**:
   - on `Free`: → `Held` by `(author, from)`. `acquisition` is this entry. `expires = created_millis +
     ttl_secs × 1000` if a TTL was given, otherwise `None`.
   - on `Held`: no effect. The claimant lost.
   - on `Pending`: from an **eligible recipient** (below), → `Held` by `(author, from)`, with this entry
     as the new acquisition and its own TTL. **This completes the handoff.** From anyone else: no
     effect. The claimant lost.
2. **`release`**: on `Held`, only from the exact owner `(fp, session)`, → `Free`. Otherwise no effect.
   A pending handoff cannot be released: the sender has already relinquished, and the recipient uses
   `decline`.
3. **`handoff`**: on `Held`, only from the exact owner, → `Pending`. `data.to_fp` is REQUIRED: the
   recipient's composite fingerprint, resolved **once, by the sender**, at posting time, which fixes F1
   and F2. `data.to_session` is OPTIONAL, and `data.to` (what the sender typed) is kept for display only.

   > **Amended 2026-09-24, during implementation.** This section said the sender resolves the recipient
   > "from its own keyring". Measured against the tree, that cannot be done by a CLI verb: the keyring's
   > petnames are reachable over the control socket only through `TrustList`, which is gated on the
   > identity passphrase (`verify_operator`, `ipc.rs`), and an agent session never holds that
   > passphrase (ADR-020 §8). So `vox room handoff --to` takes a room member's **fingerprint, or a unique
   > prefix of one**, and resolves it against the room's roster (`Request::Roster`, ungated). What the
   > design required — resolution once, by the sender, to a fingerprint no reader re-resolves — is
   > unchanged; only the lookup table differs. Petname lookup is a convenience left for a later surface
   > that has the passphrase.
   - `deadline = created_millis + data.ttl_secs × 1000`. **`ttl_secs` is REQUIRED on a handoff**, so every pending
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

   The effect: `expires = renew.created_millis + ttl × 1000`, where `ttl` is the acquiring claim's. Otherwise it
   has no effect and is reported as a stale renewal.

   The lapse check runs first, so a renewal that sorts after the holding expired finds the resource
   `Free`, or held under a **different acquisition**. It can therefore neither revive an expired claim
   nor extend a later, unrelated acquisition, even by the same session.

**Eligibility.** For a `Pending` with a `to_session`, the only eligible recipient is **exactly `(to_fp,
to_session)`**. Another session of the same harness can neither accept nor decline it. For a `Pending`
without one, **any session of `to_fp`** is eligible. The first eligible `claim` or `decline` in
canonical order decides, so one session declining frees the item for all of them: the harness declined.

**The known limit is unchanged in kind.** Resolution is deterministic but not causal between authors:
two agents' entries have no causal edge in the log (ADR-008 gives no cross-author parent), and a tie in
`created_millis` is broken by entry hash, as ADR-020 §5 records. Every node on one version computes the same state. That state need not match the
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
- **When a worker announces itself.** Before its first claim-protocol operation or work post, a session
  **MUST** have announced itself with a stamped `hello`. The participating CLI verbs post that `hello`
  when the session has not announced, so the gate does not depend on a client hook. A drain hook **MAY**
  announce earlier as a convenience. It is one message per session, which is what ADR-020 §4 reserves
  `hello` for, and it is not per-turn chatter.

  > **Two rules added 2026-09-24, during implementation — both needed for the gate to be usable.**
  >
  > - **Announce first, then check.** A verb that checked before announcing would, after the operator
  >   upgraded every worker, see only the others' *old-version* messages and refuse — and so would every
  >   other worker, and nobody would ever announce. So a participating verb posts its stamped `hello`
  >   when this session has not announced, **then** builds the version table. The first upgraded worker
  >   to act may still be refused (the others have not announced yet); the second sees the first's new
  >   version, and coordination resumes with nobody running a command for it.
  > - **A worker excludes its own fingerprint** from the table. Its own earlier messages carry the
  >   version it ran *before* an upgrade, and they must not make it refuse itself; its version is by
  >   definition the one it runs.
  >
  > The drain hook does **not** announce: the MAY above is not exercised, because an announcement on
  > the hook would put a `hello` from every session of every harness into every other agent's context,
  > and the participating verbs already make the gate independent of any hook.
- **What enforcement means.** When the version table holds any participant that does not match:
  - every claim-protocol verb (`claim`, `renew`, `handoff`, `release`, `decline`) and every `post
    --work` **MUST** refuse before posting and exit with status 3;
  - a tracker's optional Vox adapter cannot acquire a claim, so **no Vox-coordinated work can begin**;
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
   - on `Lagged`, re-read.

   > **Amended 2026-09-24: an event is a wake, never the data (F13).** Implementation found that the
   > node emits `NewEntry` **only for its own appends** (`actor.rs` `send_text`). An entry that arrives
   > from another member by sync is announced as `Synced { channel_id, applied, rendered }`, and one made
   > readable by a sender key as `SenderKeyReceived` — neither carries the row. `tail` listened only for
   > `NewEntry`, so since M19.4 it has shown this node's own posts and **never another member's**. It
   > now treats `Synced`, `SenderKeyReceived` and `Lagged` for the room as wakes: it re-reads the room
   > and emits every row it has not emitted. The re-read is whole-room rather than `since <last>`,
   > because an entry rendered late — its key arrived after it did — is not guaranteed to sit after the
   > last one emitted. This is ADR-020 §6's own rule ("the log is the delivery mechanism; any push is
   > only a wake") applied to the stream. On `Lagged`, `tail` also says so on stderr.

   Duplicates across a restart are permitted; **gaps are not**. The adapter owns the cursor and persists
   it after processing, as the drain hook does.
2. **A versioned row schema**: NDJSON, one object per row:

   ```json
   { "schema": "vox.room.row/1", "room": "<b32>", "entry_hash": "<b32>",
     "author": "<fingerprint b32>", "created_millis": 1790000000000,
     "text": "<raw>", "envelope": { … } | null, "parse_error": "…" | null,
     "op": { "id": "…", "status": "ok" | "duplicate" | "conflict",
             "group": ["<entry hash>", …] } | null }
   ```

   - Rows are in the node's local timeline order, **which is not the canonical order**, and the schema
     says so. A consumer needing a total order sorts by `(created_millis, entry_hash)`.
   - `op.status` is judged against everything the node holds: `ok` for the canonical first entry of an
     agreeing group, `duplicate` for a later one, `conflict` for every entry of a disagreeing group.
   - When a newly landed row turns an operation into a conflict, the stream **MUST** also re-emit every
     earlier row of that group with `status: conflict`. A consumer therefore learns of the change from
     the stream alone.
   - `--work REF` and `--type T` **MAY** filter on the client side. None was built: the consumer
     filters, and a filter in `tail` would be one more place for a tracker to lose a row.
3. **The folded board**: `vox room board ROOM --json`. It reports:
   - per resource: `state` (`held` or `pending`); `owner_fp`, `owner_session`, `acquisition`,
     `since_millis`, `ttl_secs`, `expires_millis`, `mine`; or `from_fp`, `from_session`, `to_fp`,
     `to_session`, `to_name`, `handoff`, `since_millis`, `deadline_millis`, `eligible`;
   - `coordination` (`ok` or `refused`) with the version table (§5);
   - `violations`: invalid operations, stale renewals, conflicts, and operations from other versions that were ignored;
   - the log position the board reflects (`position.entries`, `position.last`), and `now_millis`.

   Its schema is `vox.room.board/1`. Every claim-protocol verb also takes `--json` and prints one
   `vox.room.op/1` object — the post's `entry_hash`, `op`, `status` (`posted` or `already-posted`), its
   `outcome` in the fold and the resource's resulting `state`. Exit statuses are machine-readable: `0`
   done, `1` not done (lost, not the holder, no handoff pending), `3` version refusal (§5), `4`
   operation conflict (§6).

   The tracker records ownership from this and never reimplements the fold.

   **The adapter's read cycle** (added 2026-09-24 at the work-accountability tracker's request; it
   describes the built behaviour and adds no rule to it):
   - **Read the stream and the board from the same node.** Local order is per node: it is the order in
     which *this* node's timeline received the rows. It is append-only and survives a restart — the
     timeline is rebuilt from the sealed plaintext cache in ascending segment order, which is the order
     it was written (`channel.rs`, `store.rs`) — so an entry hash names a fixed prefix of it. That is read
     from the code; no proof restarts a node and compares the order, and one should before an adapter
     depends on it across node restarts.
   - `board.position` names the prefix the board was folded from: `last` is the entry hash of its final
     row and `entries` its length. `tail` emits the same rows in the same order.
   - To attach an ownership snapshot to the event ledger: take `board --json`, let `L = position.last`.
     If `L` is already in the ledger, the snapshot describes ownership **as of that row** — record it
     there — and, if the ledger holds the log from its first row, check that `position.entries` equals
     the number of rows up to and including `L`. If `L`
     is not yet in the ledger, the board is ahead of the stream: keep consuming `tail` until `L` arrives,
     then record it. Never attach a snapshot to a prefix it was not folded from. A mismatch in `entries`
     is a defect to report, not a case to smooth over.
   - **Ownership also changes with no row.** A lapse is a function of `now_millis`, not of the log, so
     two boards at the same position can differ. Take a fresh board at or after the earliest
     `expires_millis` or `deadline_millis` it reports, not only when a row arrives.
   - Late conflicts need no special reading: the board at `L` already folds every conflict among the
     rows up to `L`, and the stream re-emits the rows of a group that becomes a conflict later (item 2 above).
   - `coordination: refused` in the board, or exit 3 from any verb, stops the adapter (§5).
4. **Structured posting**: `vox room post ROOM --type T [--work REF] [--attempt A] [--op ID] [--to
   NAME…] [--urgent] [--data JSON] -`, with the body on stdin.
   - It fills `from` and `at` (F4). `at` comes from the git state of the working directory.
   - `from` is **the session id**: `--session`, else `VOX_SESSION`, else what the harness puts in every
     tool process's environment — Claude Code's `CLAUDE_CODE_SESSION_ID` (measured: it equals the hook's
     `session_id`) and Codex's `CODEX_THREAD_ID` (measured 2026-09-24 against Codex 0.156.1: a project
     `UserPromptSubmit` hook received `session_id` `01a0d3ae-…9115`, and the same value was in
     `CODEX_THREAD_ID` in the model's shell).
     OpenCode puts nothing there, so its plugin exports `VOX_SESSION` to every shell it runs, through
     the `shell.env` hook (measured against OpenCode 1.18.32: its shell tool triggers `shell.env` with
     `{cwd, sessionID, callID}` and merges the result into the child's environment). These are the same
     values each harness hands its drain hook as the session id, which is what lets the hook recognise
     the session's own posts.

     > **Amended 2026-09-24.** This said "`VOX_AGENT_NAME` if set, else the harness session id".
     > `VOX_AGENT_NAME` is the name a session is **addressed** by, and it is set in harness settings
     > shared by every session of the harness (`wake.rs`); used as `from`, it would make two sessions one
     > owner again — F3, reintroduced. It is not used as the session. A claim-protocol verb or structured
     > post with no resolvable session is refused rather than attributed to the whole harness.
   - It stamps `data.vox`, and honours §6.
   - With `--json`, it prints `{entry_hash, op, status}`.

   This is how workers report without hand-writing JSON, and how the tracker posts an `assign`.
   **Raw `vox room post` of a claim-protocol type is refused**, and so is a structured post whose
   `--type` is one. Such an operation would lack the stamp and the session that make it valid, and the
   verbs exist to set them. `--data` may not set `vox` or `op`.

An adapter **MUST** refuse visibly and record no owner when `board --json` reports `coordination:
refused`, or when a row's schema is not exactly `vox.room.row/1`. It must not guess across an
incompatible contract.

**The drain hook suppresses a session's own messages only when both the author fingerprint and the
session match** (F8). A row is skipped only if `author == this node's fingerprint` **and** `from ==
this session`. Another harness using the same session name, or another session on this harness, still
reaches the model. The hook names its session as the CLI does — `--session`, else `VOX_SESSION`, else the
harness's hook input — and while coordination is refused it tells the session so, every turn. The hook does not filter by work reference: a model should see what its room says to
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

**The tracker MUST therefore record planning facts in its own store at the moment they happen.** When
Vox is in use, an integration **SHOULD** also emit the matching `assign`, `blocked`, `decline`, `result`
or `failed` observation with `data.work`. Hooks are one optional convenience for doing so, not a core
tracker requirement. Vox guarantees something narrower and complete: **whatever was posted is
delivered, in a form a program can consume, without gaps.**

## Non-goals

- **Vox as the tracker.** It holds no epic, story, priority, rank, dependency, Work phase, Health,
  Source freshness, verdict or column, and builds no kanban UI.
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

  > **DONE 2026-09-24** (`ca267d5`, proof `6577864`). `work_version_proof` passes through the shipped
  > binary. **One change from the plan:** the old worker is the published **v0.2.6**, not v0.2.1 —
  > v0.2.1 speaks control-socket protocol 4 and cannot attach to a current node at all, while v0.2.6
  > speaks protocol 5; it is fetched and verified against its published SHA-256. Its receipt records the
  > divergence the gate exists to stop: v0.2.6 told its user "you hold old-work" under its old rules,
  > while the current worker refused by name. Recovery is the stale worker's first participating verb
  > (the drain hook does not announce, §5). All four mutations caught.

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

  > **DONE 2026-09-24** (`ca267d5`). `work_handoff_proof` passes. **One change from the plan:** it runs
  > on **two nodes with five sessions**, not three nodes, because of open defect F12 (two joiners cannot
  > read each other); the reason is written at the top of the proof. The nodes name each other by
  > petnames the other never uses, and their folded boards are compared field by field. Five mutations
  > caught: the handoff inert (F1), `to_session` ignored, a no-TTL holding's expiry inherited, a decline
  > returning to the sender, and the owner compared by author only (F3). Also `agentcomms_gate` (17
  > tests) folds every permutation — 120 orders of a contested claim plus handoff — to one state.

- **M21.3 — renewal bound to one acquisition.**

  *Proof* `work_renew_proof`:
  - a renewed claim outlives its original TTL, and an unrenewed one lapses;
  - a renewal posted **after** its holding expired does not revive it;
  - a renewal naming a **previous** acquisition, by the same session after a re-claim, does not extend
    the new one, and is reported as stale;
  - a renewal from another session of the same harness has no effect.

  *Mutation*: match a renewal on owner alone, ignoring `acquisition` — the re-claim case must be
  caught.

  > **DONE 2026-09-24** (`41f5180`). `work_renew_proof` passes; the late and stale renewals are written
  > onto the socket as the bytes a delayed worker on this version writes, because `vox room renew`
  > correctly reads the current acquisition and cannot produce them. Two mutations caught: matching on
  > owner alone, and matching on the harness key alone.

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

  > **DONE 2026-09-24** (`a2e20cd`). `work_op_proof` passes, with a live consumer on the other node.
  > Both mutations caught; the second (no post-read conflict check) is caught when both racing posts
  > land, which is timing-dependent and held in every run made.

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

  > **DONE 2026-09-24** (`a2e20cd` for the stream fix, `dbbdee7` for the proof). Building this found
  > **F13**: `tail` had never delivered another member's message. `adapter_stream_proof` passes: three
  > SIGKILLs, a real lag (the proof fails if none occurs — two earlier versions never lagged and failed
  > for exactly that), 1,800 of 1,800 rows with none missing, rows from the other node delivered to a
  > *live* consumer, and `board --json` equal to an independent fold. **1,800, not 2,000**, because
  > ADR-008's quota refuses a member's 1,001st entry within an hour (F14 is that the refusal is
  > reported as `Failed(Internal)`). Mutations caught: ignoring `Lagged` (a 411-row gap) and ignoring `Synced` — the
  > shipped behaviour — which the first version of the proof **did not catch**; the liveness assertion
  > was added for that reason. The planned "subscribe after reading" mutation was not used: its race
  > window is too narrow to be caught reliably, and a mutation that passes by luck proves nothing.

- **M21.6 — structured posting and self-post filtering (F4, F7, F8).** `post` with `--type`, `--work`,
  `--attempt`, `--op`, `--data` and `--json`; `from` and `at` filled in; `status` added to the
  vocabulary; raw claim-type posts refused; and the drain hook's `(author, session)` suppression.

  *Proof* `drain_self_filter_proof`, run against a live model as in M19.5b:
  - session A on harness H posts. A's next turn does not see its own post.
  - session B on the same harness H, and session "A" on a **different harness** H′, both see it.
  - H′'s post under the name "A" reaches session A on H, because the fingerprints differ.

  *Mutation*: compare `from` only — H′'s message is lost, and must be caught.

  > **DONE 2026-09-24** (`ca267d5`, proof `dbbdee7`). `drain_self_filter_proof` passes, including its
  > live half: a real OpenCode model ran `vox room post` through its shell, and the row's `from` was
  > OpenCode's own session id — named by the plugin's new `shell.env` hook. Two mutations caught:
  > comparing the session name only, and removing the plugin's `VOX_SESSION` export.

- **M21.7 — housekeeping (F9, F10).** The `--since` help text; the index rows for 018–021; the skill
  carries the §3 table.

  > **DONE 2026-09-24.** The `--since` help says 52 characters (F9); the index has rows for 018, 019
  > and 021 and a current status table (F10); the skill carries the §3 table, the exit statuses and the
  > retry rule.

- **M21.8 — rehearsal against a stub tracker.** A stub tracker, about 100 lines living inside the proof
  and not the product:
  - it mints two references, posts `assign` through `post --op`, and records state from `tail` and
    `board`;
  - two live-model workers do the work, and one is killed mid-attempt.

  *Assertions*:
  - the stub's record of each item's owner, pending handoffs and attempt history matches the log at
    every checkpoint;
  - a `release` is never recorded as Done;
  - a `result` moves an item to Acceptance at most, never to Release ready or Done;
  - `blocked` may change Health but never Work phase;
  - a `failed` attempt leaves the item retryable;
  - **the operator runs no command.**

  *Mutation*: `--pure` models, which must turn it red.

  > **DONE 2026-09-24** (proof `tracker_rehearsal_proof`). Two real OpenCode sessions on two nodes do
  > the work through their own shells; the stub tracker lives only in the proof and consumes only
  > `tail --since --json` and `board --json`. Passed twice, 123 s each. At each checkpoint: `blocked`
  > left the item Executing and set Health to Blocked; a `failed` attempt left it Ready with the failure
  > in its history; the worker killed mid-attempt lost the item only when its 45 s lease lapsed, leaving
  > it Ready; a `result` naming commit `9f3c2e1a` moved it to Acceptance and no further, and it stayed
  > there after its owner's `release`; no item's history ever contains Release ready or Done; the
  > tracker was stopped while a worker failed, released and died, and resumed from its cursor missing
  > nothing; and every work observation carries a model's own OpenCode session as `from`.
  >
  > **The mutation control changed.** The plan named `opencode run --pure`; with `--auto` it hung the
  > warm-up turn until its deadline, a red nobody can attribute, so the control removes the Vox plugin
  > from the workers' projects instead — the same thing `--pure` was to disable. It turned the rehearsal
  > red at the first claim: without the plugin no session reached the model's shell, and the model
  > improvised one (`w1`), which the proof rejected. Two earlier red runs of the control were
  > **discarded**: a stray OpenCode process left by an interrupted run was contending with them.


- **M21.9 — the drain says when a claim was lost.** Decided 2026-09-24, not built. A lapse, takeover or
  completed handoff ends a session's ownership without a message addressed to it, so a busy holder can
  keep working on something it no longer owns. The per-turn drain **MUST** tell a session, once, on the
  first turn after the change, when it no longer holds a claim it held at its previous drain, naming the
  resource and why (lapsed, taken over, handed off). A turn on which nothing changed adds nothing.

  *Proof*: through the shipped binary, a session whose claim lapses between two drains is told exactly
  once, and a session whose claims did not change is told nothing.
- **M21.10 — a `result` warns about unread addressed messages.** Decided 2026-09-24, not built. A
  redirect addressed to a session can arrive after its last drain and before it reports. `vox room post
  --type result` **MUST** still post, and **MUST** print to the caller every message addressed to that
  session that it has not yet drained, so it can follow up. It does not refuse.

  *Proof*: through the shipped binary, a `result` posted with an addressed message unread posts and
  names that message; with nothing unread it prints no warning.

## Links

- ADR-008 — the log, its ordering and tie-break key.
- ADR-018 — product proof; the standard the plan is held to.
- ADR-020 — the envelope (§4), the claim protocol this revises (§5), the drain hook (§6), the socket
  (§7), the verbs (§8) and file exchange (§11).

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
