# ADR-021: Work-item interop — the contract Vox exposes to an external work tracker

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted. Built on integrate/v0.3.0: M21.1–M21.10, in `crates/vox-agentcomms/src/{claim,ops,version,envelope}.rs`
and `crates/vox-tui/src/{room_cli,coord,agent_hook}.rs`, each with a real-binary proof in
`crates/vox-tui/tests/`. Open: the
timing-dependent M21.4 mutant and the unused M21.5 mutation (#368); `adapter_stream_proof` on
v0.3.0's single room order (V030-28, #350).
**Date**: 2026-09-23
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: agent-comms, interop, work-tracking, adapter, envelope, claims, versioning

## Context

The decider wants a work-management system, maintained by agents with no administration by him,
that turns ADRs into epics and stories and tracks priorities, dependencies and verified
completion. It is separate from Vox: Vox does not become the work tracker, and the board is not
derived from room history. The tracker in use is awa, which records progress on GitHub.
Vox's agent comms records who does what (ADR-020 §5). This ADR is the smallest contract between
them: stable work-item references, compatible event meanings, and a way for an adapter to consume
the room.

The governing constraint: one operator controls every worker and upgrades them together. So
correctness is bought by refusing to coordinate across versions, not by compatibility between
them, and the threat model is cooperating workers that may be buggy, never adversarial ones.

## Requirements

### 1. The boundary

- **1.1** Vox owns communication, delivery, waking a worker, and live ownership among workers
  (claims, folded by §4). The tracker owns what a work item is (requirements, acceptance criteria,
  epic, identity, dependencies, priority, rank), Work phase, Health, Source freshness, attempts and
  their outcomes, acceptance and release/delivery verdicts, and publishing. The tracker mints the
  work-item reference; Vox carries it opaquely, and the tracker records ownership from Vox's fold.
- **1.2** Vox MUST NOT interpret a work reference beyond carrying it, comparing it byte for byte
  and filtering by it. Vox MUST NOT store work state, check that a reference exists, or compute
  progress.
- **1.3** Progress (attempt starts, candidates, verdicts, blockers, delivery) is recorded on the
  tracker. The agent skill MUST direct agents to record progress on the tracker, and who holds a
  task only in the room.
- **1.4** The tracker MUST work without Vox and without a particular agent client. A Vox adapter
  and client hooks are optional integrations.
- **1.5** The canonical Work phases are Backlog, Designing, Ready, Executing, Acceptance, Release
  ready and Done. Health (On track, At risk, Blocked) and Source freshness (Current, Reconciliation
  needed) are independent of phase; Blocked MUST NOT be a Work phase or a column.
- **1.6** Every Vox event is an observation. Acceptance, Release ready and Done are tracker
  verdicts. A claim, branch, pull request, file overlap, green CI, merge or worker exit MUST NOT by
  itself establish a Work phase. Releasing ownership means neither Done nor failure.

### 2. Stable work-item references

- **2.1** A message about a work item MUST carry the reference in `data.work`, a string
  `<scheme>:<id>` matching `[a-z][a-z0-9-]{0,15}:[A-Za-z0-9._~/#:-]{1,112}`. The scheme is everything
  before the first colon; the id MAY contain `:` (awa's `OWNER/REPO:SOURCE:ITEM` rides as
  `gwa:robertelee78/vox:adr-021:m21.3`). The tracker MUST keep the id stable for the item's life.
- **2.2 (F16).** The CLI MUST refuse a reference of any other shape before posting, whichever flag
  carried it (`--work`, `--data`, `claim --work`), and the version gate (§5) MUST follow the
  reference wherever it was set. Vox checks the shape only.
- **2.3** `data.attempt` is an opaque correlation id. When the caller names none, a work-bound post
  from the session holding the claim on that item MUST carry a default id: the hash of the holder's
  claim (its acquisition) or of the holder's own latest `failed` for the item since that claim,
  whichever is later in canonical order. A `failed` whose operation is void (§6) seeds nothing; a
  retried `failed` seeds from its first entry. A post from a session not holding the claim carries
  no id unless it names one. An explicit `--attempt` always wins. A retried `--op` keeps its first
  id.
- **2.4** An id is not an attempt:
  - a `claim` establishes ownership only; `claim`, `renew`, `accept`, `blocked` and `status` MUST
    NOT start an attempt;
  - an attempt becomes active only when the holder posts `working` for the item; that entry's hash
    and timestamp are the attempt-start evidence;
  - `failed` ends the named attempt; the retry it seeds does not exist until a later `working`;
  - `release`, a lapse and a handoff end an active attempt, and do nothing to attempt state when
    none was active;
  - a `result` with no observed attempt start remains an assertion and MUST NOT advance a tracker's
    phase.
- **2.5** `data.op` is the operation id (§6); `data.vox` is the version stamp (§5); `data.evidence`
  is OPTIONAL, a list of `{kind, ref, sha256?}` opaque to Vox. Bytes that move between hosts use ADR-020 §11.
- **2.6** A claim on a work item MUST use the reference as its resource: `data.resource` equals
  `data.work`.
- **2.7** Every addition lives in `data`. The envelope stays at `v: 1`.

### 3. Event meanings

- **3.1** These meanings are normative for any message carrying `data.work`:

  | Type | Means | Does **not** mean |
  |---|---|---|
  | `assign` | the sender asks the addressee to take the item | ownership, which only `claim` takes |
  | `accept` | the addressee agrees and intends to claim and start | ownership, or that an attempt started |
  | `claim` | take ownership, or complete a pending handoff (§4) | that work started or the item is Executing |
  | `renew` | extend the holder's current acquisition (§4) | a new acquisition |
  | `working` | the owner reports active execution; the attempt becomes active here; a later `working` with the same id continues it | a Work phase transition by itself |
  | `blocked` | the owner cannot proceed; `data.reason` REQUIRED; cleared by the owner's next `working`, `result`, `failed` or `release` | a Work phase change, or that ownership lapsed (Health only) |
  | `status` | a progress note | a state change |
  | `result` | the attempt produced something the sender asserts meets the criteria; it SHOULD name an immutable candidate (a commit, not a branch) in `data.evidence` | an acceptance verdict, Release ready or Done; a tracker MAY enter Acceptance only for an attempt whose `working` it observed |
  | `failed` | this attempt ended without success, with `data.reason` | that the item failed or is abandoned |
  | `release` | the holder gives up ownership; an active attempt ends | Done, or failure |
  | `handoff` | the holder relinquishes and reserves the item for a named recipient (§4) | that the recipient accepted |
  | `decline` | with `data.resource`: an eligible recipient refuses a pending handoff, freeing the item; without it: the addressee refuses an `assign` | that the item is invalid |

- **3.2** A lapsed lease or lapsed pending handoff ends ownership with no message. A tracker MUST
  read ownership from the folded board (§7) and MUST NOT reconstruct it from claim messages.
- **3.3** `not-understood` (ADR-020 4.10) is the reply to an addressed work message the receiver
  cannot act on, such as one with an unknown `data.work` scheme.
- **3.4** A `status` SHOULD supersede the same `(author, from, data.work)`'s previous `status` in
  any rendering. Not built (ADR-020 9.7).
- **3.5** The skill MUST carry these meanings (M21.7).

### 4. The claim protocol

- **4.1** There is one claim protocol: `claim`, `release`, `handoff`, `renew` and a
  resource-scoped `decline`, folded in canonical order `(created_millis, entry_hash)`. No second
  vocabulary for older binaries.
- **4.2** Every operation MUST carry `data.resource`, a non-empty `from` (the session), `data.op`
  and `data.vox`. An operation missing any is invalid: it changes nothing and the fold reports it.
- **4.3 (F3).** The owner is `(author fingerprint, session)`. Two sessions of one identity are two
  owners.
- **4.4** A resource is `Free`; `Held { owner, acquisition, since, expires }`, where `acquisition`
  is the hash of the `claim` that created the holding and `expires` is `None` without a TTL; or
  `Pending { from, to_fp, to_session, deadline }`.
- **4.5** Before each operation, in canonical order, lapses MUST be applied: a `Held` whose
  `expires ≤ op.created_millis`, or a `Pending` whose `deadline ≤ op.created_millis`, becomes
  `Free`. Leases and deadlines are kept in milliseconds (`ttl_secs × 1000`).
- **4.6** `claim`: on `Free`, → `Held` by `(author, from)` with this entry as acquisition and
  `expires = created_millis + ttl_secs × 1000` if a TTL was given. On `Held`: no effect (lost). On
  `Pending`: from an eligible recipient, → `Held` by it with its own TTL, completing the handoff;
  from anyone else, no effect.
- **4.7** `release`: on `Held`, only from the exact owner, → `Free`; otherwise no effect. A pending
  handoff cannot be released.
- **4.8 (F1, F2).** `handoff`: on `Held`, only from the exact owner, → `Pending`. `data.to_fp`, the
  recipient's whole fingerprint, is REQUIRED and MUST be resolved once, by the sender, at posting
  time; no reader re-resolves it. `vox room handoff --to` takes the sender's own name for a member
  or its fingerprint (whole, or a unique prefix of at least 8 characters), resolved against the
  room's roster. `data.to_session` is OPTIONAL; `data.to` is for display only. `ttl_secs` is
  REQUIRED (the CLI stamps 3600 s by default), `deadline = created_millis + ttl_secs × 1000`, and
  the holding's expiry is replaced, not inherited.
- **4.9** `decline` with `data.resource`: on `Pending`, only from an eligible recipient, → `Free`.
  It MUST NOT return the item to the sender.
- **4.10** `renew`: `data.acquisition` is REQUIRED. It takes effect only when the resource is `Held`
  by the exact `(author, from)`, `data.acquisition` equals the holding's acquisition, and the
  holding has a TTL; then `expires = renew.created_millis + ttl × 1000` (the acquiring claim's
  TTL). Otherwise it has no effect and is reported as a stale renewal. It can neither revive an
  expired claim nor extend a later acquisition.
- **4.11** Eligibility: with a `to_session`, only exactly `(to_fp, to_session)`; without one, any
  session of `to_fp`. The first eligible `claim` or `decline` in canonical order decides.
- **4.12** Known limit, accepted: resolution is deterministic but not causal between authors (no
  cross-author parent in ADR-008; ties in `created_millis` break by entry hash). Every node on one
  version computes the same state, which need not match wall-clock order.

### 5. Workers run the same Vox version, enforced (M21.1, F11)

- **5.1** Every claim-protocol operation and every work `hello` MUST carry `data.vox`, set by the
  binary to exactly what `vox --version` reports. The CLI MUST refuse a caller-supplied `vox` (or
  `op`) key in `--data`. Comparison is exact string equality; a stamp that is not a valid semantic
  version is unknown.
- **5.2** The fold MUST apply only operations stamped with the folding worker's own version; others
  change nothing and are reported. An upgrade therefore ends every claim made under the previous
  version.
- **5.3** A worker is a participant if it is in the room's roster, its latest claim-protocol
  operation or work `hello` is not a `bye`, and either that message is within the participation
  horizon (24 hours, by the checking worker's clock) or it holds or is the target of a resource. Its
  version is that message's stamp, missing if none. A worker MUST exclude its own fingerprint from
  the table.
- **5.4** A participating verb MUST post a stamped `hello` when its session has not announced, and
  only then build the version table. The drain hook does not announce.
- **5.5** When any participant's version is mismatched, missing or unknown: every claim-protocol
  verb and every `post --work` MUST refuse before posting, with exit status 3; the drain hook MUST
  tell the session every turn that coordination is refused and why; `board --json` MUST report
  `coordination: refused` with the table. Plain conversation MUST NOT be refused.
- **5.6** The refusal MUST name the incompatible worker (fingerprint, session), its version and the
  required version (the refuser's own).
- **5.7** Known limits: workers whose clocks disagree may disagree about a participant at the
  horizon's edge, which can shift a refusal but not an owner; a binary that predates this gate
  enforces nothing, and its operations read as missing stamps.

### 6. Operation ids: real retries, explicit conflicts (M21.4)

- **6.1** Every work message and claim-protocol operation carries `data.op`. The caller SHOULD
  supply it (`--op`, `[A-Za-z0-9._-]{8,64}`) and MUST reuse it on every retry of the same
  operation; otherwise the CLI generates one.
- **6.2** An operation is identified by `(author fingerprint, op)`; op ids MUST be unique per
  author.
- **6.3** Two entries carry the same content when they agree on `type`, sorted `to`, `urgent`,
  `re`, `thread`, `from`, and `data` without `op`, as canonical JSON. `body`, `at`, `hops` and `v`
  are excluded.
- **6.4** A later entry with the same identity and content is a retry: it has no effect and is
  reported as `duplicate`.
- **6.5** Two entries with the same identity and different content are a conflict, which MUST void
  the operation: every entry of the group has no effect, in the fold and the adapter stream, and
  every one is reported. Conflict status is monotone. Vox MUST NOT pick a winner.
- **6.6** Posting with `--op`: an identical earlier entry returns its hash with exit 0 and posts
  nothing; a different one refuses with exit 4. After posting, the CLI MUST re-read the group and
  exit 4 if it is in conflict. Conflicting content MUST NOT return success.

### 7. What Vox exposes to an adapter

An adapter is a process on a node's host, with its own identity, on the workers' Vox version,
trusted like any worker. It sees what its node can decrypt. All its surfaces compose `Read`,
`Subscribe` and `Post` on the existing control socket. *Decided, not built (ADR-026):* that is the
account's one daemon socket, and an adapter names the node it acts as once per connection
(`Use { node }`, ADR-026 C-2, C-3).

- **7.1 (M21.5, F5, F6, F13).** `vox room tail ROOM --since CURSOR --json` MUST deliver every row
  after `CURSOR`, then every row as it lands, with no gap across a lag or a restart: subscribe, then
  read, then emit read rows and live rows, dropping duplicates by entry hash. An event is a wake,
  never the data: `Synced`, `SenderKeyReceived` and `Lagged` for the room MUST make it read the room
  again. Duplicates across a restart are permitted; gaps are not. The adapter owns and persists its
  cursor.
- **7.2** Rows are NDJSON with schema `vox.room.row/1`:

  ```json
  { "schema": "vox.room.row/1", "room": "<b32>", "entry_hash": "<b32>",
    "author": "<fingerprint b32>", "created_millis": 1790000000000,
    "text": "<raw>", "envelope": { … } | null, "parse_error": "…" | null,
    "op": { "id": "…", "status": "ok" | "duplicate" | "conflict",
            "group": ["<entry hash>", …] } | null }
  ```

  Rows are in the node's local order, which is not the canonical order; a consumer needing a total
  order sorts by `(created_millis, entry_hash)`. When a new row turns an operation into a conflict,
  the stream MUST re-emit every earlier row of that group with `status: conflict`. Local order MUST
  survive a node restart (F19).
- **7.3** `vox room board ROOM --json` (`vox.room.board/1`) MUST report per resource its state and
  fields (`owner_fp`, `owner_session`, `acquisition`, `since_millis`, `ttl_secs`, `expires_millis`,
  `mine`; or `from_fp`, `from_session`, `to_fp`, `to_session`, `to_name`, `handoff`,
  `since_millis`, `deadline_millis`, `eligible`), `coordination` with the version table, `violations` (invalid
  operations, stale renewals, conflicts, other-version operations), `position` (`entries`, `last`)
  and `now_millis`. Every claim-protocol verb takes `--json` and prints one `vox.room.op/1` object.
  Exit statuses: `0` done, `1` not done, `3` version refusal, `4` operation conflict, `5` not every
  member agreed (ADR-020 5.4).
- **7.4** The adapter read cycle: read the stream and the board from one node; `board.position`
  names the prefix folded; record a snapshot at row `position.last` once the stream has delivered
  it, never at a prefix it was not folded from; a mismatch in `entries` is a defect to report. A
  lapse depends on `now_millis`, so the adapter MUST take a fresh board at or after the earliest
  `expires_millis` or `deadline_millis`. `coordination: refused` or exit 3 MUST stop the adapter.
- **7.5 (M21.6, F4).** `vox room post ROOM --type T [--work REF] [--attempt A] [--op ID] [--to
  NAME…] [--urgent] [--re E] [--data JSON] -` MUST fill `from` and `at` (from the working
  directory's git state), stamp `data.vox` and honour §6. `from` is the session id: `--session`,
  else `VOX_SESSION`, else `CLAUDE_CODE_SESSION_ID`, else `CODEX_THREAD_ID`; OpenCode's Vox plugin
  exports `VOX_SESSION` to every shell through its `shell.env` hook. A claim-protocol verb or
  structured post with no resolvable session MUST be refused. A raw post of a claim-protocol type,
  or a structured post whose `--type` is one, MUST be refused.
- **7.6** An adapter MUST refuse visibly and record no owner when the board reports `coordination:
  refused` or a row's schema is not exactly `vox.room.row/1`.
- **7.7 (F8).** The drain hook MUST skip a row only when its author is this node and its `from` is
  this session. It MUST NOT filter by work reference.
- **7.8** Vox MUST NOT add a `Request` variant, a server-side filter, a push to the tracker or a
  per-tool-call event for the adapter.
- **7.9 (M21.9).** The drain MUST tell a session, once, on its first turn after the change, when it
  no longer holds a claim it held at its previous drain, naming the resource and why: its claim
  lapsed (and the item is now held by `<name>/<session>`, reserved for one, or free), or a claim
  that crossed it was ordered first (V210-168). A loss the session caused (its own latest operation
  on the resource is a `release` or `handoff`) MUST NOT be reported. Nothing changed, nothing said.
- **7.10 (M21.10).** `vox room post --type result` MUST post, and MUST then name, on stderr and as
  `unread_addressed` in `--json`, every message past the session's drain cursor that is not its own
  and is addressed to its node (V210-161). It MUST NOT refuse.

### 8. What replay can and cannot recover (a tracker obligation)

- **8.1** An emitted event the adapter missed is recoverable by replay from its cursor. A fact never
  posted (an unreported blocker, an assignment made only in prose, a decision in someone's head) is
  not recoverable by any replay. Git is authoritative for source and integration facts only.
- **8.2** The tracker MUST record planning facts in its own store when they happen. When Vox is in
  use, an integration SHOULD also post the matching observation with `data.work`. Vox guarantees
  only that whatever was posted is delivered, machine-readable, without gaps.

### Non-goals

Vox MUST NOT be the tracker (no epic, story, priority, rank, dependency, phase, Health, verdict,
column or kanban UI); MUST NOT coordinate across versions; MUST NOT change the wire or bump the
socket protocol for this contract; MUST NOT validate a reference against a tracker; and does not
defend against a dishonest worker (session names, stamps and op ids are declarations by trusted
keys).

### Known limits

F16's gate half (a `--data` reference passes the version gate) follows
by construction and is not separately proved; `work_version_proof` drives the gate through `--work`
only. M21.8's assertions that a `release` is never Done and a `result` reaches Acceptance at most
test the stub tracker's own rules, not Vox. The M21.4 no-post-read mutant is timing-dependent and
M21.5's subscribe-after-read mutation is used by no proof (#368).

## Consequences

- The contract is small: reserved `data` keys, one claim protocol, a meaning table, four CLI
  surfaces.
- Workers on one version compute the same owner; a worker on another is refused loudly, by name.
- A retry is safe and a conflict is never silent.
- Upgrading ends every live claim; workers re-claim.
- A stale worker blocks coordination for the whole room until upgraded, removed, or silent for one
  horizon (24 hours).
- A conflict can void an operation a tracker already acted on; the tracker handles it.
- An adapter sees only what its node can decrypt (ADR-020 §3).

## Related ADRs

- [ADR-008](ADR-008-replicated-authenticated-log-and-sync.md) — the log, its order and tie-break
  key.
- [ADR-018](ADR-018-quality-bar-and-product-proof.md) — product proof.
- [ADR-020](ADR-020-agent-comms.md) — the envelope (§4), claims (§5), the drain hook and wake (§6),
  the socket (§7), the verbs (§8) and file exchange (§11).
- [ADR-023](ADR-023-room-lifecycle.md) — the room's order.

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
