# ADR-050: An Agent Turn Is Finished, or Declared Uncertain

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
  of 2026-11-13 ("post review can accept them too"), after the tenth independent review by
  GPT-6.1-Sol passed revision 11 (`adr-050-sol-review-10`); proposed 2026-11-12. Nothing in it
  is built: every requirement is written as what the code is to do. It takes
  over ADR-040 revision 2's NW-10 (the OMP turn journal, exit code 79, `--omp-finish`, the
  `finishPending` ladder, check-before-poison) and its question Q3; ADR-040 revision 3 lists
  NW-10 under "Moved requirements" and does not reuse the id. This ADR is the design record
  for fix-list item 30 (a turn that lands on a refusal permanently poisons an OMP conversation).
  **What v0.4.31 fixes here**: a committed turn is finished by Vox after any refusal, daemon
  restart or killed hook (the commit refused while the daemon is stopping, and the
  post-decision `news_publication` check, measured by E-30 run `f`); the turn journal and its
  finish verbs; stamped held claims; the extension finishing a committed turn across a restart
  or a killed hook; truthful notices; the retirement retry; a reservation released when a
  hook dies before writing. **What it does not change**: a terminal provider error on a step
  that carried room news still ends that conversation's use of Vox, in one sentence, by the
  decider's rulings of 2026-11-13 (ledger rows 36, 67 as applied by 79). Revisions 2–7
  (2026-11-13) answered the six independent reviews (`adr-050-sol-review` … `-6`) and the task
  cut's defects; revision 8 (2026-11-13) applies row 79 and withdraws the "delivered after an
  error" class those reviews had narrowed five times; revision 9 (2026-11-13) answers the
  seventh review (`adr-050-sol-review-7`): the retry exemption is corrected to the
  provider-client boundary, and five proof defects are fixed; revision 10 (2026-11-13)
  answers the eighth (`adr-050-sol-review-8`): three retry boundaries, not two, and B2's
  shipped verdict; revision 11 (2026-11-13) answers the ninth (`adr-050-sol-review-9`): 8f′'s
  assertions. "Review record" lists every finding.
- **Date**: 2026-11-12; revisions 2–11 2026-11-13
- **Deciders**: Robert E. Lee
- **Tags**: OMP, agent hook, sessions, attention, cursors, durability, exactly-once
- **Related**: ADR-018, ADR-020, ADR-021 (M21.9), ADR-028 (RR-1, K-19), ADR-029 (P420-OR-6),
  ADR-031 (JL-4), ADR-040 (NW-1, NW-3, NW-4, NW-8, NW-9); in this release ADR-041 (RS-7, RS-9,
  RS-12), ADR-042 (TR-11), ADR-044, ADR-045 (J7, ruling 32), ADR-046, ADR-047, ADR-048,
  ADR-049
- **Inputs**: the operator's Mac daemon logs of 2026-11-12 (the sessions he had to replace);
  RcaTrust (T2, runs `s3`, `c1`, `c2`, `w1`); plan D §30; ADR-040 revision 2's NW-10 and its
  revision note; the two ADR-040 reviews and the ADR-050 review, every finding in this lane
  checked against the `v0.4.30` tree (commit `8d71ab337`); the installed OMP's source
  (`/opt/oh-my-pi`, `v18.18.0-17-gf2b795ba74`; the installed binary is 18.20.0 and the cited
  functions were read at that tree); the decider's rulings of 2026-11-13 (cross-ADR ledger rows
  32, 36, 49, 67, 79); the experiment E-30 rig and receipts under `/opt/vox-evidence/v0431/adr050/`
  (see "Experiments").

## Context

### What the operator saw

On 2026-11-12, on the Mac, after each `vox daemon --restart` while agents were mid-turn, one or
more OMP conversations printed `Vox: delivery in this conversation is uncertain; start a new
native OMP conversation to use Vox. Restarting or resuming cannot confirm earlier delivery` and
never carried Vox context again. The operator replaced those agent sessions by hand, repeatedly,
during his work day. `vox room sessions` still listed them as open.

### Root cause at v0.4.30 (fix-list item 30)

Citations are to the tree at tag `v0.4.30`. The hook that prepares an OMP turn
(`vox agent hook --omp-prepare`, `crates/vox-tui/src/agent_hook.rs`) does this, in order:

1. Under a per-session file lock (`omp_uncertainty_lock`, `agent_hook.rs:262-306`), it selects
   the news: reads each room's cursor file, decides how many rows are shown (`shown_in`,
   `:3366-3393`), reserves attention receipts with fresh tickets (`Operation::Prepare`,
   `:3473-3512`).
2. It writes `cursors/omp-uncertain/<session>` (`omp_uncertainty_begin`, `:308-341`) holding the
   session, node, room, notice id and the receipts, and **nothing about what the turn will
   change**: the cursor each room moves to, the ahead and pulling deltas, the held claims, the
   offers shown, the markers (`:319-335` vs `RoomDrain::commit`, `:2976-3023`, which computes
   them from live objects at commit time). Of each receipt it keeps room, instance, session,
   ticket and sources, not the recipient's `opening` and `identity`
   (`attention.rs:101-112`), which the daemon checks on every receipt operation
   (`channel/attention.rs:103-107`; `ledger.rs:276-298`).
3. It emits the context envelope and blocks on stdin for OMP's decision (`omp_decision`,
   `:519-531`: `commit\n` or `cancel\n`).
4. On `commit` it takes the room-pause publication lock again (`news_publication`,
   `:3596-3600`, `:3760`; the no-news path's twin `:3271-3275`), runs `check_omp_opening`
   (`:216-252`: the registration check and an attention `Resolve` against the daemon, `:3601`),
   then the markers, `offered.commit`, the cursor commits, `Received{ticket}` for each receipt
   (`:3639-3657`), `mark_read`, and only then removes the file (`:3674`). On `cancel` it
   cancels the receipts and removes the file (`:3585-3594`), writing nothing else. A Drive turn
   (`VOX_OMP_DRIVE=1`, `:380-389`) writes the marker, emits an empty envelope, and after
   `commit` runs `check_omp_registration` (`:386-387`) before removing it.
5. Any error between the decision and `:3674` exits 1 with the file in place. The extension sees
   an enveloped non-zero exit and calls `poisonSession` (`omp-extension.ts:259-265`). From then
   on `--omp-check-uncertainty` (`cli.rs:3418-3436` → `omp_uncertainty_lock`, `:298-302`)
   answers 78 while the file exists, `register()` maps 78 to `refusal = "permanent"`
   (`omp-extension.ts:516-526`), and the conversation is dead.

The trigger on the Mac was ADR-040 NW-8's window: the `Resolve` in step 4 was refused
`attention waits for current computer trust` while a sibling node started. Any refusal does it:
`room governance is refreshing` (RcaTrust `run-s3`, `calls-2.log:26-36`, receipt lost in the
reboot of 2026-11-13; recorded in `rca-RcaTrust.md`), `the selected Session is no longer open`,
and, measured by E-30 run `f`, the post-decision `news_publication` against a daemon that is
stopping (`room pause state could not be read; news and its cursor are held: the selected node
could not be reached: the daemon is stopping`, `:3760`). The marker was written for a turn whose
decision is unknown (ADR-029 P420-OR-6) and is applied to a turn whose decision the hook has
already read. Two further defects make a plain "finish the turn later" impossible at v0.4.30:
the marker lacks the effects (first ADR-040 review, finding 3), and `SavedHashes::merge` refuses
its own completed replacement (`:725-732`: the file-identity check runs before the no-op check;
finding 4).

Two latent defects found while enumerating writers and ledger transitions for this ADR:

- A hook killed after `Prepare` and before the envelope (the extension's 30 s watchdog,
  `omp-extension.ts:244`, or any death) leaves its tickets `output_pending` in the attention
  ledger. `Ledger::begin` then returns `None` for that session while `outputs_pending != 0`
  (`attention/ledger.rs:627-634`), so the daemon dispatches no further notice to it until the
  Session closes (`:1130-1131`); the hook's `cancel_attention_receipts` (`:3681-3720`) runs only
  on error paths the hook lives to take. No marker records those tickets.
- For an attention-triggered turn the daemon's `begin` records an `attempt` (`:672`) and the
  hook's `Admit` marks it admitted (`:698-707`). `CancelPrepared` clears tickets only
  (`:790-821`); the attempt is cleared by `dispatch` (`:709-748`) or when its sources are
  received (`reconcile_attempt`, `:967-976`). A cancelled or dead turn leaves the attempt, and
  `begin` refuses while `attempt.is_some()` (`:627`): no automatic notice reaches that session
  again until an ordinary turn drains the attempt's sources or the Session closes (ADR-050
  review F3).

### What exists after a model step that ends in an error (installed OMP, shipped extension)

The extension decides `commit` only for a step that ends with one request, one marker and a
known stop reason (`omp-extension.ts:1267-1268`). Any other end of an injected step runs
`finish(op, null)`: `op.done = true`, no decision, the hook's stdin closed without a line
(`:190-209`), and **`poisonSession`** (`:206`). The hook reads an empty line, exits 1
(`omp_decision`, `:526-530`), and the marker stays: at v0.4.30 a terminal provider error, a
rate limit the harness does not retry, or an unknown stop reason after an envelope ends the
conversation's use of Vox exactly as item 30's refusal does. The callers of that no-decision
end: `message_end` with an error or an unknown stop reason (`:1282`), a fence mismatch at
`before_provider_request` (`:1245`, a session transition while the step is in flight), a
watcher succession (`:459`) and a retire (`:799`, session switch or shutdown) with an
injected operation, and `agent_end` with an operation still open (`:1349`). Three retry
boundaries exist in the harness, and the extension sees two of them: (1) an **HTTP retry below
one payload callback** (a transient 408/429/5xx retried by the transport inside one provider
attempt, after `onPayload` was called once, `providers/openai-completions.ts:983-1000`) is
invisible to the extension: one `before_provider_request`, then the step's messages; Vox is
unaffected; (2) a **provider-attempt retry** (`withReplaySafeStreamRetry`,
`packages/ai/src/utils/empty-completion-retry.ts:111-180`, calls the attempt factory again;
each attempt calls `onPayload`, `openai-completions.ts:960`, forwarded to extensions,
`coding-agent/src/sdk.ts:4721-4722`) repeats `before_provider_request`: the shipped extension
already counts the builds and treats the second as ambiguity (`omp-extension.ts:1241-1253,
1267-1268`), so such a step is uncertain under TJ-3; (3) OMP's **automatic step replay**
(`turn-recovery.ts:1562-1596`) is decided later, in `agent_end` maintenance
(`agent-session.ts:4975-4990, 5223-5231`), **after** the failed step's error `message_end` has
already been forwarded to extension handlers (`:4768-4769`, `:3967-4003, 5943-5963`). So an
error `message_end` after injection ends the conversation's use of Vox even if OMP then
replays the step.

Six reviews (2026-11-13) tried, with this ADR, to find a sound rule under which such a turn
could be counted delivered to the same conversation; each found a path inside the harness that
broke the inference about what the model saw or did: a provider that hides its history in
blobs (`packages/ai/src/providers/cursor.ts:6631-6688`), a recovery that reparents the branch
(`turn-recovery.ts:1404-1437`), a transport that sends without `onPayload`
(`providers/pi-native-client.ts:45-56`), a speculative task launched from argument deltas and
stripped from the terminal message (`task/speculative-launch.ts:225-260`;
`agent-loop.ts:2712-2740`), streamed events delivered unordered (`agent-session.ts:3943-3999`),
hosted tools whose blocks are discarded (`anthropic.ts:651-688`), compaction and rollover
(`session-maintenance.ts:1806-1810`), and, last, tool definitions carried inside the system
prompt under an owned dialect with `tools: undefined` (`agent-loop.ts:2031-2037, 2228-2239`),
so that even an empty `payload.tools` proves nothing about what the model could call. The
class is withdrawn for v0.4.31 ("The decider's answers"). The one daemon fact that stays
(third review, finding 3): an attention attempt the daemon dispatched and the extension
accepted (`DispatchOutcome::Accepted`, `ledger.rs:732-735`) has no expiry; `begin` refuses
while it exists (`:627-634`); it is cleared only by a later `Dispatch` outcome, by
`reconcile_attempt` when its sources are received (`:967-976`), or by the Session's close.

### Evidence status

- KNOWN by code: everything above.
- Reproduced on the instrumented binary: RcaTrust `run-s3` (`calls-2.log:26-36` exit 1 then
  78; `shim-2.log:14-15` the warning; `timeline.log:58-77` carries `RCA` traces, so this is not
  a release-asset receipt). That the hook had read `commit` before the refusal is INFERRED from
  the shim's accepted line 23 ms before the exit.
- Release runs `c1`/`c2` held a turn across a restart and show rc=0: the commit was released
  after the first node's Ready, so the refusal window was missed. They are not this red.
- Release-asset red: **measured** by experiment E-30 run `f` (2026-11-13 19:25Z; receipts
  `/opt/vox-evidence/v0431/adr050/f/`; the binary is the GitHub release asset
  `vox-aarch64-apple-darwin`, sha256 `f3bf4ec2…b463`, `f/asset.sha256`). The rig's own verdict
  line, `f/timeline.log:61` and `f/summary.out:61`: `VERDICT: PRODUCT red | held carried news:
  True | prepare rcs: ['0', '0', '1'] | uncertain line: True | check rc=78: 1 | news-after
  shown: False`. What the product did (`f/shim.log`, `f/calls.log`, `f/A-daemon.log`): the
  daemon's wake for the post `news-held` started an aside turn whose envelope carried it
  (`shim.log:21`), and the shim held that turn between the envelope and `commit`; `vox daemon
  --restart` was issued and the commit released 0.31 s later, while the old daemon answered
  `the daemon is stopping`; the hook's post-commit publication check failed (`calls.log:15-17`,
  pid 40316: `room pause state could not be read; news and its cursor are held: the selected
  node could not be reached: the daemon is stopping`, exit 1); the extension printed `Vox:
  delivery in this conversation is uncertain; start a new native OMP conversation to use
  Vox…` (`shim.log:27`); after the restart `--attention-register` answered 0 and
  `--omp-check-uncertainty` answered 78 (`calls.log:20-24`); the next post, `news-after`,
  readable by `omp-work` 0.5 s later, was never injected in three probe turns and no
  `--omp-prepare` ran again. That is the sequence item 30 describes and E-30 was written to
  show: a committed turn, one refusal between the commit and the end of its bookkeeping, and a
  conversation dead for good. The receipt also shows, incidentally, the restarted daemon's
  `attention selection remains pending: attention waits for current computer trust`
  (`A-daemon.log`, item 28, ADR-040 NW-8).

### What the other harnesses do

Claude Code and Codex run `vox agent hook` from a `UserPromptSubmit` hook; OpenCode's plugin
runs it with `--format opencode` and no `--omp-prepare` (`opencode-plugin.js:974-975`). None of
them has a decision step: the hook emits and commits its cursors in the same process, with
`strict = false` (`agent_hook.rs:3627-3634`: every commit failure is a stderr line, never an
exit), and no uncertainty marker exists for them. They do not have item 30's defect. What they
acknowledge is the hook's **output**, not the model's reading of it: the OpenCode plugin waits
for the hook to finish (`runHook`, `:974`) and only then parses and injects its output
(`:976-1002`); by then the cursor is moved and `Received` sent. A harness that dies between the
hook's exit and the injection skips that news for good; a hook that dies after emitting and
before its cursor write shows it again. This is pre-existing and this ADR does not change it;
TJ-9 states it plainly and gives them the one repair they share.

## Terms

- **Turn**: one OMP prompt step for which the hook prepares Vox context: the envelope, OMP's
  decision, and the bookkeeping that records what was shown.
- **Envelope**: the one JSON line the hook prints (`emit_receipts`): Vox's own notices, the room
  text, the attention receipts.
- **Decision**: OMP's word on the envelope, written by the extension into the hook's stdin:
  `commit` (the model's step accepted the context: one request, one marker, a known stop reason,
  P420-OR-6) or `cancel`. An operation that ends with neither (`finish(op, null)`,
  `omp-extension.ts:206`: an ambiguous request, an error, an unknown stop reason) has **no
  decision**.
- **Effect**: one durable change the turn makes once committed: a cursor file's new content, a
  held-claim record, an offers record, a marker file, an attention receipt, a read mark.
- **Turn journal**: the hook's durable per-session file holding the turn's effects, its state,
  and the decision. One file, `cursors/omp-turn/<session>`.
- **Journal states**: `admitting` (written before an attention notice is admitted; holds the
  notice and its recipient), `prepared` (holds every effect; nothing has been printed and
  nothing will be until the next state), `publishing` (from now on the envelope may have
  reached the model), `decided` (`decision: commit | cancel`), `done` (every effect applied;
  notices for the person may remain).
- **Uncertainty tombstone**: `cursors/omp-turn/uncertain/<session>`, a small durable file
  written by temp + rename when a turn is classified uncertain, before anything else is moved
  or removed. While it exists every verb of the session answers 78. It is the per-Session
  uncertainty marker of ADR-029 P420-OR-6.
- **Unresolved turn**: a turn whose journal is `publishing` and whose operation ended with no
  decision; it is resolved at that moment by TJ-3 as not shown or as uncertain.
- **Provably not shown**: an unresolved turn for which the extension holds the operation-scoped
  fact that nothing was injected: its journal is `admitting` or `prepared` (no byte printed),
  or the extension parsed no envelope line from the hook (`!enveloped`), or it never spliced the
  message into the request (`!op.injected`). An injected turn is never "not shown".
- **Hook verbs**: `--omp-prepare`, `--omp-finish` (new), `--omp-release-notice` (new),
  `--omp-check-uncertainty`, `--attention-register`.
- **The ladder**: the extension's bounded retry schedule, 1, 2, 4, 8, 16, 30 s
  (`omp-extension.ts:356`), used here as `finishPending`, independent of `confirmed`.
- **Exactly-once**: a committed message is shown to the model in exactly one turn.

## The decider's answers (2026-11-13)

- **Q3, row 36.** A possibly shown turn with no durable decision keeps the conversation
  uncertain for good; nothing is shown again. Chosen against the recommendation; his concern is
  an instruction acted on twice. ADR-029 P420-OR-6's "never cleared or replayed" stands.
- **Q7, row 67.** Put to him as a story in which the agent had run nothing: "treat it as
  delivered". Applied only where both premises are guaranteed. Five reviews showed the second
  premise ("the agent ran nothing") cannot be established by Vox's extension for any request
  that could call a tool, and the sixth that even an empty native `tools` field does not show
  that (tools ride inside the prompt under an owned dialect).
- **Q8, row 79 (17:35 PST).** On those facts: **"Keep the safe outcome: after such a failure
  the conversation stops using Vox, says so in one plain sentence, and you start a new
  conversation to keep using Vox there. No risk of a double action."** Not chosen: keep going
  in the same conversation under a checked harness setup. This ADR is written to that answer:
  TJ-3 has three outcomes and no fourth.

*Not chosen in v0.4.31: the checked middle setup* (sixth review B4). For the inspected OMP
tree, ordinary local tools could stay available while speculative task launching is disabled
and provider-run tools are excluded; then local actions wait for a successful terminal response
and only optional speculative reads could repeat. It would need an explicitly supported OMP
version and configuration (early launches off, no hosted tools, no custom execution paths),
the effective tool set checked by Vox at each request under the dialect in use, and a proof of
that boundary; none of it exists, and the harness updated itself twice on 2026-11-13.

## Requirements

### 1. The guarantee

- **TJ-1. A turn with a decision is finished exactly once, by Vox, without the person; a turn
  that ended with no decision is shown later, once, only when nothing was injected, and is
  otherwise uncertain for good, with nothing of it marked shown; Vox never shows news twice by
  its own doing.** Precisely:
  - *Exactly-once* holds for every message whose turn has a `commit`: it is shown in that turn
    and never again as news (its cursor effects are applied, once, however many times finishing
    runs), and no message that arrived after the selection is swallowed (the journal fixes the
    selection; finishing never re-selects).
  - *Shown later, once* holds only when nothing was injected (TJ-3 (ii)): the journal never
    reached `publishing`, or the extension parsed no envelope line, or it never spliced the
    message. Its reservations are cancelled, its admitted attempt released, no cursor moves,
    and the news is shown in a later turn, once.
  - *Uncertain for good* is every other end without a decision (TJ-3 (iii)): a terminal
    provider error or unknown stop reason after injection, on every transport, whatever tools
    were or were not offered; a switch, update or shutdown mid-step; OMP dying mid-step; a death
    between the `publishing` rename and the first printed byte (nothing shown, but not
    provably); an unreadable journal. It costs one conversation, never a repeat by Vox's doing.
  - *Never permanently unusable by a defect*: a journal with a decision never answers 78; a
    conflict or an obsolete target finishes the journal with one notice to the person (TJ-7);
    every verb on a session with a committed journal finishes it first. The only permanent
    state is the uncertain one the decider chose, and TJ-8 names every event that reaches it.
  - *Why*: item 30; the decider's answer to Q3; ADR-050 review F4 (every possibly shown case
    goes through the chosen policy, never a silent replay).

### 2. The journal

- **TJ-2. Before an attention notice is admitted the hook MUST write the turn journal holding
  the notice and its exact recipient (`admitting`); before any reservation it MUST extend it
  with every effect the turn will make and the exact recipients and tickets of its
  reservations (`prepared`); it MUST move it to `publishing` before printing any byte; it MUST
  move it to `decided` after reading the decision line and before any effect; a journal that
  replaces a `done` journal MUST carry that journal's undelivered notices.** The journal is
  `cursors/omp-turn/<session>` (replacing `omp-uncertain/<session>`), one JSON document, written
  with temp + rename + fsync and a parent-directory sync (as `omp_uncertainty_resolved` does
  today, `:347-352`), always under the session lock. At v0.4.30 `omp_prepare` resolves the
  recipient and admits the notice (`Operation::Admit`, `:432-461`) before `drain` begins; the
  `admitting` journal is written as the **first act** of a notice turn, before the `Resolve`,
  holding the notice id and route (the recipient is added after the `Resolve`), so a hook
  killed anywhere after its first write leaves a record that can release the attempt (second
  review R1; third review finding 3). The window before that first write is owned by the
  extension (TJ-8, "The accepted attempt with no journal"). Fields:
  - `session`, `node`, `room`, `instance`, `generation` (the registration the turn was prepared
    under: `VOX_OMP_INSTANCE`, `VOX_OMP_GENERATION`), `record` (the extension's record id for
    this wake, passed as `VOX_OMP_RECORD`; new, used by TJ-3), `selected_at` (ms).
  - `notice`: for an attention-triggered turn, `{id, route, recipient?}`: id and route from
    `VOX_OMP_NOTICE` and `saved.attention.route` written before the `Resolve`; the complete
    recipient the `Resolve` answered (`:408-431`) added by a second rename before `Admit`;
    absent otherwise. Used to release the attempt (TJ-4, F3, R1): a cancel path that finds no
    recipient resolves it itself (TJ-4).
  - `receipts[]`: `{recipient: {room, instance, session, opening, identity}, ticket,
    sources[]}`: the **complete** `Recipient` (`attention.rs:101-112`), the ticket drawn
    **before** the journal is written, so a reservation never exists without a journal naming
    its exact recipient and ticket (F1).
  - `rooms[]`, one per drained room: `key`; `cursor_before` (the identity `(dev, ino, len)` of
    the cursor file as read for the selection, or `absent`); `cursor_to`; `ahead_add[]`,
    `ahead_remove[]` (exact, from `read_to(shown)`, `:2942-2972`); `pulling_before`,
    `pulling_add[]`, `pulling_remove[]`, `scan_to` (`Pulling::commit`, `:2863-2879`);
    `held_remove[]` (the resources reported lost this turn, `lost`, `:980-1073`) and
    `held_set[]` (`held_now`, the board's answer; absent when the board could not be read);
    `mark_read[]` (the exact list `mark_read` sends, `fresh[..shown]` minus owed rows,
    `:3772-3776`).
  - `offers` (the exact bytes `offered.commit` writes, `:3034-3051`, or absent); `markers[]`
    (the joined and room-note marker paths, `:3609-3626`).
  - `state: admitting | prepared | publishing | decided | done`; `decision: null | commit |
    cancel`; `notices[]` (filled while finishing, TJ-7: `{id, kind, room}`, each once);
    `carried[]`: the `notices[]` of the `done` journal this one replaced, copied into the new
    journal in the same rename that replaces it, delivered in this turn's envelope (TJ-6) and
    dropped at the `decided` rename (by then the extension has read the envelope and answered);
    a cancel or an uncertain classification of a journal with `carried[]` writes it back as a
    `done` journal holding those notices instead of removing it (R7).
  The journal is bounded by the turn: one page of rows per room, the ahead window of 128
  (`AHEAD_WINDOW`), one pulling page of 64, one offers body under `MAX_INJECTED_BYTES`.
  - *Why*: ADR-040 review finding 3; the second review's schema request (the exact `MarkRead`
    list); the dangling-ticket defect (journal before `Prepare`); F1 (the complete recipient);
    F3 (the notice); F4 (a state written before any output, so "possibly shown" is on disk
    before it can be true).
  - *Changes*: `agent_hook.rs`: `omp_uncertainty_begin` → `turn_journal_admitting(notice)`
    between `:431` and `:432`, and `turn_journal_prepared(selection)`, called before the
    `Prepare` loop (`:3413`) with the tickets drawn there; the effect
    computation of `RoomDrain::commit`, `Pulling::commit`, `read_to` and `mark_read` moves into
    pure functions that produce the journal rows; `turn_journal_publishing` runs after the
    publication lock and the pre-envelope checks (`:3525-3552`) and before `emit_receipts`;
    `omp_decision` is followed by `turn_journal_decided`. The no-news OMP path (`:3252-3282`)
    and the Drive path (`VOX_OMP_DRIVE=1`, `:380-389`) write the same journal with empty rows
    (no receipts, no effects) and the same states; a Drive turn's finishing has no step to
    apply and removes the journal, and its post-decision `check_omp_registration` (`:386-387`)
    is deleted with the others (TJ-4): a registration that changed after the decision makes
    nothing obsolete in an effect-less turn.
  - *Deleted*: `cursors/omp-uncertain/`, `omp_uncertainty_begin/resolved`; the pre-envelope
    `cancel_attention_receipts` calls (`:3462, 3466, 3506, 3517, 3529, 3541, 3549, 3559`): a
    hook that fails before `publishing` exits with its `prepared` journal in place, and the next
    verb cancels exactly from it (TJ-8), so no cancellation is best-effort any more.

### 3. The decision

- **TJ-3. A decision is the hook's journaled line, or the one the extension supplies for the
  same operation; a turn that carried room news has three outcomes and no fourth: committed
  when its step completes without error; not shown and offered again only when nothing was
  injected; uncertain in every other case.** On reading `commit\n` or `cancel\n` the hook MUST
  rename the journal `decided` before any later step. The extension MUST pass the wake's record
  id (`VOX_OMP_RECORD`) to `--omp-prepare`; the journal carries it. A `publishing` journal whose
  writer is dead (lock free) is settled only by the extension, never by a verb on its own:
  `--omp-finish` and `--omp-check-uncertainty` answer `{"turn":"undecided",…}` and change
  nothing; the extension calls `--omp-finish --decided commit|cancel --record <id>` or
  `--omp-finish --uncertain --record <id>`.

  *The rule.* For an operation that ends (`message_end` `:1282`; the fence mismatch `:1245`;
  succession `:459`; retire `:799`, reached from `session_shutdown` `:1076-1089` and the session
  transitions; the prepare's close handler `:249-275`; `finish(op, null)` no longer poisons,
  `:206` is deleted; `agent_end` `:1349` ends nothing: an injected operation that has not
  reached `message_end` stays as it is):
  (i) **commit** as today: one request, one marker, a known stop reason, no error
  (`:1267-1268`); the accepted record is appended (`:1277`). "One request" is one
  `before_provider_request` for the step, as today: a transient error retried by the transport
  **below** that one payload callback is invisible and is not an end here; a provider-attempt
  retry that calls `onPayload` again is a second build, and the step is ambiguous, (iii), as
  the shipped extension already rules (`:1250-1253`); an error `message_end` that OMP later
  replays by itself **is** an end (iii): the replay is decided after the error reached the
  extension (`agent-session.ts:4768-4769, 4975-4990`), and the replayed step injects nothing
  for a record already finished. The one-build rule is never relaxed because no assistant
  event arrived between two builds.
  (ii) **cancel**: the extension itself decided it before injection (`finish(op, "cancel")`,
  `:1212-1237`), or it holds the operation-scoped fact that nothing was injected: `!enveloped`
  (its own parse of the hook's stdout found no envelope line, `:246-258`), `!op.injected` (it
  never spliced the message into the request, `:1232-1233`), or the hook's journal is
  `admitting`/`prepared` (TJ-8). Nothing else is evidence: not the absence of
  `before_provider_request`, of a marker, of content, of a tool call or of a `tools` field.
  (iii) **uncertain** (`--uncertain`): every other end. A terminal provider error, a rate limit
  the harness does not retry, or an unknown stop reason after injection, on every transport,
  whatever tools were or were not offered (the sixth review's P1: tool definitions can ride
  inside the prompt under an owned dialect, `agent-loop.ts:2031-2037, 2228-2239`, so the
  request's own fields do not show what the model could call; this is why the "delivered after
  an error" class of revisions 3–7 is withdrawn, not narrowed again); a fence mismatch
  (`:1245`); a succession or a retire with an injected operation (`:459`, `:799`); the hook
  died during the step **and** OMP died before its close handler ran; `register()` after an OMP
  restart finds `undecided` with no accepted record on the current branch (an accepted record
  there → `commit`, as for any committed turn).
  **The hook died with OMP alive** (the close handler sees a signal exit or an enveloped exit
  before any end): the operation stays in flight and its end is classified by (i)–(iii) when it
  comes; a decision it already holds (`op.decision` set) is supplied at once.

  The hook MUST accept a supplied decision only for a `publishing` journal whose `record`
  matches and whose lock it holds; it then records it exactly as a read line and finishes
  (`commit`) or cancels (`cancel`). `--uncertain` writes the tombstone and retires the Session's
  attention (TJ-8). A supplied decision for a `decided` or `done` journal is a no-op answered 0
  (or 79 while finishing). The hook never infers a decision from the daemon's state, from the
  journal's age, or from its own `publishing` state.
  - *Why*: ADR-040 first review's NW-10 assessment; its second review's window 3; ADR-050
    reviews F4, R3, and the third to sixth reviews' findings on the withdrawn class; the
    decider's rows 36, 67 and 79.
  - *Changes*: `omp-extension.ts`: `prepare` passes `VOX_OMP_RECORD`; `finish(op, command)`
    applies the rule and calls `finishPending(record, outcome)`; retire (`:799`) resolves an
    unresolved record as uncertain; `agent_end` (`:1349`) no longer ends an injected operation.
    `agent_hook.rs`: `--omp-finish` accepts `--decided`, `--uncertain` and `--record`.
  - *Deleted*: `poisonSession` at `:206` and `:263` (the extension poisons in exactly one way:
    when a verb answers 78, `:252` and `:518`, kept); `finish(op, null)` at `:271` and at
    `:1349`; the pending state, the re-placement of an envelope into later requests, the
    marker-carrying-request record, `--omp-finish --pending --request <n>`, the tool-less
    premise, the per-transport "delivered" tables and Alternative T of revisions 4–7.

### 4. Finishing: every effect idempotent; cancel applies no effect

- **TJ-4. A `decided` journal is finished by `finish_turn(journal)`, under the session lock, by
  the hook that wrote it or by any later verb of the same session; for `commit` every effect
  step is safe to run again, a step whose target is gone is obsolete and done, a step whose
  target was changed by another writer is a conflict reported once and never overwritten, and
  a `NotYet` is waited for and then handed to the extension (TJ-6); for `cancel` only the
  reservations and the admitted attempt are released and no effect is applied; finishing never
  selects news.**

  *Commit*, in order, each step skipping what is already applied:
  1. **Markers** (joined, room-note): `write_private_file_unique`; `AlreadyExists` is done.
  2. **Offers**: write the journaled bytes; repeatable under the lock (the only other writer is
     a hook of this session, TJ-5).
  3. **Per room, pulling then cursor** with `SavedHashes::apply(path, before, outcome)`: open the
     file; if its content equals the outcome (cursor equals `cursor_to`, every add present,
     every remove absent) → done; else if its identity equals the journaled `before` → replace
     atomically (today's merge body, `:734-804`); else if the file is absent and the daemon
     reports the room is not held (`client.rooms()`; ADR-049's purge removes a left or ended
     room's cursor and held files, `paths.rs:688-709`, `leave_save.rs:286`) → obsolete; else →
     **conflict**: record `{id, "cursor-conflict", room}` in `notices[]`, leave the file as it
     is, continue. This replaces `merge`'s identity-first precondition (`:725-732`). The scan
     file (`pulling-scan`) is a cursor-only file and follows the same rule.
  4. **Held claims**, per room, by stamped set merge under the held file's own lock (TJ-5):
     the held file's lines are `resource\tacquired_ms` (new format; `note_held` stamps a claim
     or renewal with its time, replacing an existing line for the same resource; v0.4.x has no
     prior-release compatibility requirement). The result is: every line of `held_set` (keeping
     the current file's stamp for a resource it already has, else `selected_at`), plus every
     line of the current file whose stamp is **≥ `selected_at`** (a claim or renewal made
     after the selection, including a reacquisition of a resource in `held_remove`), and
     nothing else. Written only when it differs; the same however many times it runs. Equal
     stamps keep the line: one possible repeated lapse notice rather than a missed one (F6).
     When `held_set` is absent (the board could not be read) the step is skipped, as today
     (`:3014`).
  5. **Receipts**: `Received{recipient, sources, ticket}` per entry with the journaled complete
     recipient. The ledger skips a consumed ticket (`attention/ledger.rs:843-849`:
     `output_pending != Some(ticket)` → continue), so a repeat is a no-op. The daemon's answers
     `the selected Session is no longer open` (the Session closed, `channel/attention.rs:91`)
     and `attention selection changed; refresh and retry` (the opening was replaced: the
     current exact recipient differs from the journaled one, `:103-107`) are **obsolete,
     opening ended**: record `{id, "receipt-obsolete-opening", room}`, done. `ChannelNotOpen`
     or the room absent from `client.rooms()` is **obsolete, room gone**: record `{id,
     "receipt-obsolete-room", room}`, done. No delivery is invented; no replacement recipient
     is resolved (F1). A transport failure, an unknown answer, or a daemon that is down is
     **not** obsolete: it is a not-yet for this step (TJ-6).
  6. **Read marks**: `MarkRead{channel_id, entries}` per room from `mark_read[]`. The room skips
     hashes already marked (`pending_text/read.rs:166-168`), so a repeat is a no-op. A permanent
     refusal (`this identity has left the room`, `this room has ended`, `read selection
     changed; refresh and retry`, `ChannelNotOpen`) is obsolete and done, as today's best
     effort (`:3784-3799`); a `NotYet` (ADR-040 NW-1's kinds) is waited for.
  7. **Done**: rename the journal `done`. A `done` journal with an empty `notices[]` is removed
     at once with a directory sync; one with notices is removed by the verb that delivers them
     (TJ-7).

  *Cancel* (F2): `CancelPrepared{recipient, sources, ticket}` per entry (idempotent,
  `ledger.rs:790-821`; an `admitting` journal has none); for a journal with `notice` (resolving
  the recipient first when the journal has none yet: `Resolve` for the session; "the selected
  Session is no longer open" makes the notice obsolete, done),
  `Dispatch{attempt, outcome: Held("the turn that carried this notice was not delivered")}` with
  the journaled recipient, notice id and route, which clears the attempt whether or not it was
  admitted and blocks no route (`ledger.rs:711-721`; `dispatch` compares notice id, route and
  recipient only; a missing or different attempt is a no-op or `changed`, both done) so the
  daemon's next `begin` can dispatch again (F3, R1); then remove the journal, or, when it
  carries `carried[]`, rewrite it as `done` with those notices (R7). No marker, offer, cursor,
  held or read-mark write: the shipped cancel branch writes nothing either (`:3585-3594`).

  Steps 1–4 need no daemon except the "room held" question in step 3's absent-file case; when
  the daemon is down that question is a not-yet, and the step is retried, so a cursor file is
  never recreated for a room the node has dropped. The post-decision `news_publication`
  (`:3596-3600`, `:3271-3275`: the room-pause publication lock taken again after the decision,
  whose refusal is the exit 1 E-30 run `f` measured), `check_omp_opening` (`:216-252`, `:3601`,
  `:3276`), `check_native_notice` (`:3603`) and the Drive path's `check_omp_registration`
  (`:386-387`) are **not** steps and are deleted: once the decision is journaled, a pause
  admitted after the envelope changes nothing that was shown (the pause fence was held across
  the envelope, `:3525-3536`), and the opening's current state decides only whether a receipt
  is obsolete, which the daemon says itself in step 5. That removes item 30's triggers, the
  measured one included.
  - *Why*: ADR-040 review finding 4; its second review's F9 and window rows 4–9 and 12; ADR-050
    review F1, F2, F3, F6, F7 (the two obsolete kinds).
  - *Changes*: `agent_hook.rs`: `finish_turn`, `cancel_turn`, `SavedHashes::apply` (keeping
    `merge`'s body), `apply_held`; `note_held`, `load_held`, `save_held` and `lost_claims`
    read and write the stamped format and take the held file's lock; `check_omp_opening` stays
    for `--omp-prepare`'s pre-envelope checks only (`:3128`, `:3261`, `:3546`).
  - *Deleted*: `news_publication` at `:3596-3600` and `:3271-3275`; `check_omp_opening` at
    `:3276` and `:3601`; `check_native_notice` at `:3603`; `check_omp_registration` at
    `:386-387`.

### 5. Every writer of the conversation's state

- **TJ-5. Every writer of a session's cursor and attention state is named here and covered by
  the lock, the merge rule or the daemon's own idempotence; a writer not in this table MUST NOT
  be added without adding its row.** At v0.4.30:

  | State | Writers | Covered by |
  |---|---|---|
  | cursor file `cursors/<room>-<session>` (cursor + ahead) | hook drain (`save_read`, `:817-832`, any harness); daemon purge deletes it (`remove_room_cursors`, `paths.rs:688-709`, from `leave_save.rs:286`) | session lock for every hook verb of the session, OMP or not (new: `drain` takes it for any `--session`, so a manual `vox agent hook --session <id>` of an OMP session cannot interleave); absent file + room not held = obsolete |
  | `pulling/`, `pulling-scan/` | hook drain only (`Pulling::commit`, `:2863-2879`); **not** deleted by the purge (gap noted to ADR-047/049; `apply` treats them as the cursor) | session lock; outcome-or-identity |
  | `held/<room>-<session>` | hook drain (`save_held`, `:940-953`); `vox room claim` (`room_cli.rs:3814-3818`) and `vox room renew` (`:3456-3458`) via `note_held` (`:962-969`, read-modify-write, **no lock today**, resource names only); daemon purge deletes it | the held file's own lock (new, `.lock` beside it, like the cursor's `:718-725`), taken by `note_held` and by step 4; stamped lines; the stamped merge (F6, F9) |
  | `offers/<session>` | hook drain only (`offered.commit`) | session lock; rewrite of journaled bytes |
  | `joined/<room>-<session>`, `omp-room-note/<session>` | hook drain (`write_private_file_unique`) | `AlreadyExists` = done |
  | `omp-room-joining/<session>` | `--attention-register` (`:2178-2196`), guarded by "neither marker exists" | read by prepare only; not a turn effect |
  | `omp-turn/<session>` (the journal) | the hook verbs of the session | session lock; one writer at a time; a second verb gets 75 (TJ-6) |
  | attention ledger: `output_pending`, `attempt`, `notice_admitted`, `Delivered` (`Begin`, `Admit`, `Prepare`, `Received`, `CancelPrepared`, `Dispatch`) | the hook (any harness) and the daemon's attention loop through the daemon; the daemon's own Session close (`ledger.rs:1130-1131`) | idempotent by ticket, and by (recipient, notice id, route) for the attempt; every ticket and admitted notice is in a journal before it exists (TJ-2), so a `prepared` or cancelled journal releases them (TJ-4, TJ-8) |
  | read marks | the hook's `MarkRead`; the TUI's own reads | `was_read` skip in the room |
  | session registration (`wake.rs`) | ADR-040 NW-9's one serialized writer per node: the hook sends `SessionRegister` with `state: Idle` on `Stop` and `Busy` on every other event, and none for `VoxAttentionRegister` (`registration_only`); `record_omp_state` and every other registration update go through that writer, never a hook-process write | not turn state; the journal records `instance`/`generation`; a mismatch makes receipts obsolete, never a refusal |

  Two hooks of the same conversation: the extension can run a `finishPending` timer, a next
  `--omp-prepare`, and `register()`'s `--attention-register` + `--omp-check-uncertainty` at the
  same time (`omp-extension.ts:505-530, 1198, 1210`). The lock serializes them; the loser gets
  75 and retries on its own ladder (TJ-6), never a poison and never a second envelope. A dead
  process releases its kernel lock; the lock file's presence is not a lock.
  - *Why*: ADR-040 second review's F9 and its row "two hooks of the same conversation"; F3's
    attempt state.

### 6. Exit codes and the route through the extension

- **TJ-6. A committed journal that cannot be finished within the hook's wait exits 79,
  `commit recorded; Vox finishes this turn's bookkeeping`; the extension owns finishing with a
  ladder that does not depend on `confirmed`; 75 is retried on the same ladder; 78 is answered
  only while the session's uncertainty tombstone exists; a killed hook is checked before it is
  poisoned; every completion path carries the journal's notices.**
  - *Hook side.* Before the envelope, a `NotYet` from the daemon (ADR-040 NW-8's case: the
    `Resolve`, `Admit` or `Prepare` refused while a sibling starts) is answered as today by a
    non-enveloped non-zero exit that the extension's close handler retries (`scheduleRetry`,
    `:253-256`); the `prepared` journal it leaves is cancelled by the next verb (TJ-8). After
    the decision is journaled, a `NotYet` from the daemon in any step (typed,
    ADR-040 NW-1, carrying `wait_ms` as NW-3 allows the hook to send) is waited for up to 5 s in
    `--omp-prepare` (the prepare child has no watchdog after the envelope, `omp-extension.ts:287`)
    and up to 5 s in `--omp-finish` (its helper is killed at 30 s, `:328`); a daemon that is
    down, a transport failure or an unknown answer is not waited for. Past the wait the verb
    exits **79**. The code table of every verb:

    | Verb | 0 | 79 | 75 | 78 | other non-zero |
    |---|---|---|---|---|---|
    | `--omp-prepare` | envelope emitted, decided, finished (or cancelled) | a committed turn is pending (finished first, still pending): no envelope this turn | session lock held by another verb; registration absent (`:373-376`, as today) | tombstone present; or a `publishing` journal with a free lock (the prepare writes the tombstone first: a new turn cannot begin while the previous one is unresolved) | pre-envelope refusals as today (NW-8's case: the extension retries) |
    | `--omp-finish` | nothing pending, or finished | still pending | lock held | tombstone present (written first for an unreadable journal, TJ-8) | — |
    | `--omp-check-uncertainty` | as `--omp-finish` (it finishes a committed journal first) | as `--omp-finish` | lock held | as above | — |

    The structured line is the last stdout line of `--omp-finish` and `--omp-check-uncertainty`,
    the only stdout of a non-enveloped `--omp-prepare` (79, 78), and a field `turn` of the
    envelope of a successful `--omp-prepare` (an old extension ignores unknown fields,
    `:284`): `{"turn":"finished"|"pending"|"undecided"|"uncertain"|"cancelled","record":"<id>","retired":true|false|null,
    "notices":[{"id":"<record>:<kind>:<room>","kind":"receipt-obsolete-opening"|"receipt-obsolete-room"|"cursor-conflict","room":"<name>"}]}`.
    `notices[]` holds the `notices[]` of the session's `done` journal and the `carried[]` of
    its current journal (F7, R7); `--omp-finish` and `--omp-check-uncertainty` remove a `done`
    journal **after** their stdout is flushed; `--omp-prepare` drops `carried[]` at its
    `decided` rename, after the extension has read the envelope and answered. Every stderr line
    follows ADR-042 TR-11 (first clause lower case, prerequisite in NW-1's words): `commit
    recorded; Vox finishes this turn's bookkeeping when <prerequisite words>`.
  - *Extension side.* One per-session `finishPending(record)`: runs `--omp-finish` on the ladder
    1, 2, 4, 8, 16, 30 s (then 30 s repeating) until 0, or until 78 **with** `retired: true`
    in the structured line (a 78 with `retired: false` keeps the ladder running: the Session's
    retirement is still owed, third review finding 4); on 79 or 75 it continues; it runs
    whether or not `confirmed` is true, whether `refusal` is `permanent`, and whether or not a
    registration attempt is in flight
    (ADR-040 review finding 5: `scheduleRetry` returns while `confirmed`, `:354-359`;
    `register()` too, `:505-508`). The `hook()` helper's close decoder (`:340-345`) MUST
    classify 79 as `pending` and 75 as `temporary`, never `permanent`; 78 stays `uncertain`.
    The prepare close handler (`:249-275`): on an enveloped exit after `finish(op, command)`
    ran (`op.done`), it MUST call `finishPending` with that end's classification (TJ-3: a
    decision, or `--uncertain`); on an enveloped exit before any end (`!op.done`, `:266-271`:
    the hook died while the model works) it MUST keep the operation in flight and let its end
    be classified when it comes (TJ-3, "the hook died with OMP alive"); on a non-enveloped
    exit it MUST call `finishPending`, which supplies `cancel` (TJ-3 (ii)). `register()`'s
    `--omp-check-uncertainty` step MUST treat 79 as "registered; finishing" (set `confirmed`,
    keep the ladder running), `undecided` as "resolve per TJ-3's `register()` clause now", and
    78 as today
    (poison). The extension consumes `notices[]` from every
    structured answer, including the envelope's `turn` field, and shows each id once per OMP
    life (TJ-7). `--omp-prepare` of a session with a committed journal finishes it first and,
    if it cannot yet, exits 79 non-enveloped: that turn gets no Vox context, nothing is lost
    (the news is still unread), and the next turn tries again.
  - *Why*: ADR-040 review finding 5 (no consumer; the watchdog case poisons); its second
    review's "two hooks" row (75 missing from the ladder) and row 7 (transport failure must
    reconcile as 79, not become permanent); ADR-050 review F7 (notices from a successful
    prepare).
  - *Changes*: `agent_hook.rs`: `OMP_COMMIT_PENDING = 79`; `--omp-finish`;
    `--omp-check-uncertainty` finishes first; the envelope's `turn` field. `cli.rs:3418-3436`:
    dispatch. `omp-extension.ts`: `:249-275`, `:284` (read `turn`), `:340-345`, `:505-530`;
    `finishPending`; `VOX_OMP_RECORD`. Exit 79, `--omp-finish`, `--decided`, `--uncertain`,
    `--record`, the structured line and the `turn` field are hook surface, not the control
    protocol (ADR-041 RS-12); the typed attention answer with `wait_ms` is ADR-040's and is
    counted in RS-12's one bump to 12.
  - *Deleted*: the `report("Session registration is no longer present; reacquiring it")`
    branch for 75 at `:255` when the 75 came from the lock (the `poisonSession` deletions are
    TJ-3's). *Added*: `--omp-release-notice <id>` (TJ-8), hook surface.

### 7. What reaches the person

- **TJ-7. An obsolete receipt and a cursor conflict are each told once, by the extension, in
  one fixed sentence; nothing else of a finished turn is shown; the hook's stderr is never
  displayed.** The hook records each notice in the journal's `notices[]` before it is first
  printed; a `done` journal with notices stays on disk until a verb has flushed them in its
  structured answer (TJ-6), so a notice survives any hook death and is printed again until
  delivered; the extension deduplicates by `id` (`<record>:<kind>:<room>`) within one OMP life,
  so a notice is shown once, or once more after an OMP restart that fell between the print and
  the `notify`. The extension calls `report` (`ctx.ui.notify`, `:316-318`) with the fixed text
  (ADR-042 TR-11 form):
  - `receipt-obsolete-opening`: `Vox: a notice shown earlier in room <name> could not be marked delivered: this conversation's Session opening there has ended. Nothing in this conversation was lost.`
  - `receipt-obsolete-room`: `Vox: room <name> is gone; a notice shown earlier there could not be marked delivered. Nothing in this conversation was lost.`
  - `cursor-conflict`: `Vox: this conversation's read position in room <name> was changed outside Vox; news already shown may appear once more.`
  The first two cost the room's members one missing `delivered` state for that notice in
  `vox room sessions`; the third names the one case where a repeat is possible, caused by a
  writer outside Vox's hook (a person editing the cursor file), not by Vox. None is a reason to
  start a new conversation and none says so. The hook's own stderr stays undisplayed
  (`omp-extension.ts:335-336` drains it, correctly: it may carry private data).
  - *Why*: ADR-040 second review's F18; its first review's question 6 (decided-turn identity
    loss: finish the local bookkeeping, report the undelivered receipt, invent no delivery);
    ADR-050 review F7 (deliver from every completion path; distinguish opening ended from room
    gone).
  - *Changes*: `omp-extension.ts` `finishPending` and the envelope reader; `agent_hook.rs`
    `finish_turn`'s `notices[]` and `done` retention.

### 8. The uncertain state, and the two states that are not

- **TJ-8. An `admitting` or `prepared` journal with a free lock is cancelled exactly; a
  `publishing` journal with a free lock is classified by the extension (TJ-3) or becomes
  uncertain; the uncertain state is a durable tombstone written before anything else is moved,
  with the Session's attention retired without redelivery; while the tombstone exists every
  verb answers 78 with today's sentence and nothing of the turn is marked shown.** When a verb
  takes the lock it first looks for the tombstone (78 if present), then at the journal:
  - `admitting` or `prepared` (the hook died before the `publishing` rename, including the
    extension's pre-envelope watchdog kill and a death between `Admit` and the selection): run
    the cancel path of TJ-4 (`CancelPrepared` per journaled recipient and ticket;
    `Dispatch(Held)` for the journaled notice), remove the journal (or keep its `carried[]` as
    `done`), continue. No byte was printed, so nothing was shown; the news and the notice are
    offered again by the daemon and shown in this or a later turn, once.
  - `publishing`: `--omp-finish`/`--omp-check-uncertainty` without a flag answer `undecided`
    (exit 0) and change nothing; the extension classifies it per TJ-3. `--omp-finish
    --decided`: finish or cancel. `--omp-finish --uncertain`, or `--omp-prepare` (the extension
    starts a new turn only when the previous operation is over, `:1192`, so a `publishing`
    journal at prepare time means the extension did not classify it: OMP was restarted and
    TJ-3's `register()` clause found nothing, or the classification call was lost): **write
    the tombstone**
    (temp + rename + directory sync), then retire the Session's attention (below), then move
    the journal to `omp-turn/archive/<session>.<time>`; answer 78.
  - unreadable (not valid JSON, or a schema this binary does not read): write the tombstone
    with reason `damaged` **first**, then move the bytes to `omp-turn/archive/<session>.<time>`
    for diagnosis; answer 78. Never answer 0 and never discard: the file is the only local
    record of reservations that may still be pending in the ledger (R2, F8). A journal is
    written by temp + rename, so this case is disk corruption or a downgrade, not a crash
    window; a crash between the tombstone and the move leaves both, and the next verb finishes
    the move.
  - *Retiring the Session's attention* (R4): the tombstone's turn may have shown its
    reservations, so they are never cancelled (that would offer the news again). The verb that
    writes the tombstone sends `Received{recipient, sources, ticket}` for every journaled
    receipt (marking those sources `Delivered`: consumed, never requeued, `ledger.rs:859-867`)
    and, for a journaled notice, `Dispatch{attempt, Held}` (the attempt is cleared, its
    remaining sources stay queued for a later notice; a wake for them reaches a poisoned
    conversation, whose `queue()` refuses it, `:182`, and the daemon's dispatch records
    `NotSent` with the route blocked, `:725-729`). The tombstone records `retired: false` until
    the daemon has accepted both; every later verb of the session retries them before
    answering 78, and the answer carries `retired`. **The owner of the retry** is the
    extension's `finishPending` ladder for that session, which keeps running on a 78 whose
    `retired` is `false`, independent of `confirmed`, of `refusal === "permanent"` and of any
    injection (TJ-6), and is restarted by every watcher `ready` frame (`:434-437`) while the
    old conversation is open (third review finding 4). If the person closes the old
    conversation before that, the Session's close releases the ledger's side without
    requeueing (`ledger.rs:1130-1143`: `Unavailable`, "the exact Session is no longer open").
    An unreadable journal has no receipts to send; its Session's pending outputs are released
    only by that close, and the tombstone says so (`retired: null`).
  - *The accepted attempt with no journal* (third review finding 3, K0): the daemon's loop
    dispatched a notice and the extension accepted it (`answer("accepted")`, `:1029`); the
    prepare child it then spawned died before its first write (`admitting`). The daemon holds
    an accepted, unadmitted attempt with no expiry (`ledger.rs:627-634, 732-735`). The
    extension owns it: its close handler, on a non-enveloped exit of a prepare whose record is
    an attention record, runs `vox agent hook --session <id> --omp-release-notice <notice id>`
    on the ladder until 0; that verb resolves the session's recipient (`Resolve`), sends
    `Dispatch{attempt: {recipient, notice_id, route: saved.attention.route}, Held}` (a
    recipient that no longer matches the attempt answers `changed`: the attempt belongs to a
    closed opening and is released by its close; "no longer open": obsolete; both 0), and the
    daemon's next `begin` dispatches again. If OMP dies too before that, the attempt waits for
    the person's next prompt turn, whose `Received` of the sources empties it
    (`reconcile_attempt`, `:967-976`): today's behavior, stated.
  - `register()` and `--omp-check-uncertainty` with a tombstone: 78, as today;
    `--omp-prepare`: 78, no envelope.
  - *What the person sees and must do.* The conversation prints, once, one sentence, which
    replaces today's `omp-extension.ts:86` (and its overflow twin at `:80`): `Vox: this
    conversation has stopped using Vox after a failed step; start a new native OMP conversation
    to keep using Vox. The new conversation may be shown room news this one already saw and
    may have acted on.` Ordinary chat and tools in the conversation continue; only Vox's context
    stops (the extension injects nothing more). The person starts a new native OMP
    conversation; registration there is fresh, and the room's unread news is selected for it by
    its own cursor: the messages the uncertain turn carried are shown to it again, once, as news
    (retirement marks them delivered for the old Session only, `ledger.rs:859-867`). Restarting
    or resuming the old conversation does not change this; nor does OMP's own automatic replay
    of the failed step, which runs after Vox has already stopped. (A transient error the
    transport retries underneath one request, before any error is shown, is a different thing
    and changes nothing; a retry that rebuilds the request is a second request and ends Vox's
    use in that conversation as well, under TJ-3.) Closing
    the old conversation is not required; `vox room sessions` lists its Session until it closes
    (third review finding 6; sixth review B1; seventh review P1).
  - *Which events lead here.* Every end of a turn that carried room news without a decision,
    except one where nothing was injected (TJ-3 (ii)); on every transport alike: a provider
    error or an unknown stop reason that reaches the extension as the step's `message_end`
    after injection, whether or not OMP replays the step afterwards; a provider-attempt retry
    that repeats the payload callback (a second build in one step); (an HTTP retry below the
    one payload callback is invisible and changes nothing); a
    session switch, branch or tree move, an
    update succession or `session_shutdown` with an injected step in flight (retire `:799`, the
    fence mismatch `:1245`, succession `:459`); OMP dying between the envelope and the step's
    end with no accepted record on resume; the hook dying during the step **and** OMP dying
    before its close handler ran; an unreadable journal. A daemon restart, a refusal, lock
    contention and a hook killed by the 30 s helper watchdog never lead here. No frequency is
    claimed: no receipt measures how often a terminal error lands on a Vox-injected step (sixth
    review B3). At v0.4.30 every event above produces the same dead conversation; what changes
    is everything else (the status paragraph).
  - *Why*: the decider's answer (ledger row 36); F4; F8 and R2 (a durable terminal record
    before any move); R3 (the no-decision ends, named); R4 (retirement owned and
    non-requeueing); third review findings 3 (the no-journal attempt), 4 (the retry owner), 6
    (same-Session suppression only); ADR-029 P420-OR-6 ("never cleared or replayed",
    unamended).
  - *Changes*: `agent_hook.rs`: the verbs' tombstone check and journal triage; the retirement
    requests; `OMP_UNCERTAIN` and 78 kept for the tombstone only. `omp-extension.ts`: the one
    sentence replaces `:86` and `:80`; `poisonSession` is called only from the two places a verb
    answers 78 (`:252`, `:518`).
  - *Deleted*: revision 1's `repeat/<session>` record and its `Vox could not confirm…` line
    (Q3-B's path); revision 2's `uncertain` journal state and `damaged/` directory (the
    tombstone and `archive/` replace them).

### 9. The other harnesses

- **TJ-9. Claude Code, Codex and OpenCode hooks acknowledge the hook's output, not the model's
  reading of it; they may repeat news after interrupted bookkeeping and may skip news when the
  harness dies between the hook's exit and its injection; this ADR changes neither, and gives
  them only the dangling-reservation repair.** A hook without `--omp-prepare` has no decision
  step, so it writes no turn journal: a journal would make its output wait on an fsync for a
  guarantee it cannot offer (the harness never tells Vox what the model received). These hooks
  keep committing in-process with `strict = false` (a failed cursor write repeats news next
  turn, as today, `:3009-3013`), and they take the session lock while draining (TJ-5), so a
  manual hook of an OMP session cannot interleave with a finishing turn. Their `Prepare`
  reservations MUST be written to a one-line ticket file `cursors/tickets/<session>` (the
  complete recipients, tickets and the admitted notice, as TJ-2's `receipts[]` and `notice`)
  before `Prepare`, and removed after `Received`; a later hook of the session that finds the
  file runs TJ-4's cancel path from it first. That is the whole of TJ-2 they need. Their
  refusals are not poisons at v0.4.30 and stay that way. What a person may see from them is
  unchanged: a message repeated once after a hook died mid-bookkeeping, or missing when the
  harness died after the hook finished.
  - *Why*: ADR-050 review F9 (the revision 1 "at-least-once" was overstated: the OpenCode plugin
    injects after `runHook` returns, `opencode-plugin.js:974-1002`; `claude_injector.rs` and
    `codex_app_server.rs` carry no delivery state); the OpenCode plugin's input receipts
    (`:979-981`) share the ticket path.
  - *Changes*: `agent_hook.rs` `drain` for `omp_registration.is_none()`: the lock, the ticket
    file.

### 10. Proof

- **TJ-10. The proof is one journey through the real OMP extension in ADR-041 RS-7's file,
  `an_omp_conversation_survives_a_daemon_restart_proof.rs`; a focused hook act for the kill
  points stays in `agent_hook_proof.rs`; every assertion is what a person or the model sees;
  no assertion reads a file under `cursors/`; every act is staged with processes and files
  only, inside the macOS guest or the Linux VM (ruling 32).** The journey extends RS-7's
  staging (the real `omp-extension.ts` under the host shim with a file-backed session store
  that follows OMP's persistence rules as ADR-041 RS-9 names them: `getEntries`/`getBranch`/
  `appendEntry`/`ensureOnDisk`/`getSessionFile`, a non-throwing append whose failure latches, a
  deferred file until `ensureOnDisk`, a readback from the file; RcaTrust's `shim-hold.mjs` is
  the model; the exact events the journey needs of the shim are listed under "What RS-7's
  journey must host") and
  adds the acts below. (Revision 1's hosting of ADR-042 TR-13's agent-invocation act is
  withdrawn: ADR-042 r9 withdrew that act with TR-14 under the decider's ruling Q1, ledger row
  22.)

  *Oracle for "shown once" (ADR-040 second review F17; ADR-050 review F10; sixth review P2).*
  The shim logs every `appendEntry` of `vox-context-staged` with its `id`, `marker` and content,
  every `before_provider_request` payload, every `message_end` with its `stopReason` and
  `errorMessage`, and every `vox-context-accepted`. A **delivery identity** is a staged record's
  `id`. A message is **delivered** at the first step whose payload contains that identity's
  marker and which ends at `message_end` with a known stop reason and no `errorMessage`; later
  steps whose payloads carry the same marker are that identity's history and are not counted.
  The oracle: each posted message's text belongs to exactly one delivery identity that is
  delivered, and no staged record created after a turn's `commit` contains a message text that
  an earlier delivered identity already carried (a second insertion as news). "Nothing later
  is swallowed": a message posted after the held turn's selection is delivered under a later
  identity. A red the oracle cannot count (a payload the staging keeps the marker out of) is
  asserted on the sentence of TJ-8 instead; every act names its assertion.

  *Apparatus knobs, in one place (test-knobs builds only; absent from the installed release).*
  `VOX_TEST_TURN_HALT_AFTER=<step>` aborts the hook after the named step: `spawned` (after
  start, before any file is written), `admitted`, `prepared`, `prepare-sent`, `publishing`,
  `decided`, `markers`, `offers`, `pulling:<room>`, `cursor:<room>`, `held:<room>`,
  `received`, `mark_read`, `done`, `tombstone`, `archive`. `VOX_TEST_TURN_PAUSE_AFTER=<step>`
  with `VOX_TEST_TURN_PAUSE_FILE=<path>` pauses the hook after the named step (`prepare-sent`
  or `decided`) until the file is removed; the act that set it removes it once the event it
  waited for is observed. A daemon that any client starts during a staged outage (a
  registration hook starts one when none answers, `daemon_client.rs:96-135` from
  `agent_hook.rs:2562`, item 41) is APPARATUS for every act that stages an outage.

  *v0.4.30 verdict per act (release template rule 10).* Act 1: PRODUCT red, measured (E-30 run
  `f`). Acts 2, 4, 6, 7, 9, 9b, 11, 12 and the knob variants B2, E2, 8b′: CANNOT MEASURE (the
  knob or the verb is absent at the tag); their knob-free controls, each green on v0.4.30: act
  2, a claim of `Y` made after an ordinary committed turn is reported lost once when it
  lapses; act 4, an unheld committed turn delivers `m1` once; act 6, `commit` shows `m1` once
  and `cancel` shows it again; act 7, the same switch with no notice in flight shows no Vox
  line; act 9 and 9b, an attention-triggered turn not killed delivers its notice once with no
  prompt; act 11, a hook not killed; act 12, a second `--omp-prepare` during the hold exits 75;
  E2, act 5's main case. B2 has no green control on v0.4.30: its assertion is act 3's TJ-7
  sentence, which the shipped extension never receives, so B2's staging without the halt is
  PRODUCT red there, as act 3 is. Act 3: PRODUCT red
  (v0.4.30 prints its `uncertain` line instead of TJ-7's sentence). Act 5, main case (OMP and
  the hook both die): green on v0.4.30 (it prints its `uncertain` line too); exists for
  Mutants E and F; act 5's OMP-alive variant: PRODUCT red (v0.4.30's close handler calls
  `finish(op, null)` for a dead enveloped child, `omp-extension.ts:266-271`, which poisons,
  `:190-206`, where the variant requires no sentence). Act 8: 8a–8e and 8f green on v0.4.30
  (they assert the line v0.4.30's equivalent prints), exist for their mutants; 8f′ (two builds
  in one step → uncertain) green on v0.4.30 too (the shipped extension already counts builds,
  `omp-extension.ts:1250-1253`); 8f″ (one build, an HTTP retry underneath, a clean completion
  → committed) green on v0.4.30 (the retry is below the extension's view). Act 10: CANNOT
  MEASURE (no `--omp-finish` at v0.4.30). A
  changed red is recorded in the act's own text here and in the release gate's receipts
  (ADR-045).

  *Act 1, the restart during a held turn (the release red, measured: E-30 run `f`).* Peer posts `m1`; the daemon
  wakes the conversation (an aside turn, P420-OR-6); the shim holds **that** turn between the
  envelope and `commit` (E-30 run `d` showed that a prompt turn after the post has nothing left
  to show). The apparatus stops the scratch daemon
  (SIGTERM to its own pid) and keeps it stopped for 5 s, then starts it again. The shim
  releases `commit` while the daemon is absent (the hook's receipt step gets no daemon: 79 at
  once after the local effects). Peer posts `m2` after the daemon is back. Assert: the notify
  log holds no `delivery in this conversation is uncertain`; `m1` delivered once (the held
  turn), `m2` once (a later turn); an offer shown in the held turn is not shown again; `vox
  room sessions` lists the session open with its last-seen advanced; the agent's claim of `X`
  held before the turn and lapsed during the outage is reported lost exactly once. v0.4.30
  red, PRODUCT, measured on the release asset by E-30 run `f` ("Evidence status": the held
  turn's `--omp-prepare` exits 1 against the stopping daemon, the notify log carries the
  `uncertain` line, the next `--omp-check-uncertainty` answers 78, the next post is never
  shown; `/opt/vox-evidence/v0431/adr050/f/`).
  (A daemon any client starts during the 5 s is APPARATUS.)
  *Mutant D (act 1 and act 6): keep `merge`'s identity-first precondition in `apply`
  (`:726-730`).* After the kill or the outage, the first `--omp-finish` finds the cursor file
  already replaced by this turn, sees identity ≠ `before`, and reports `cursor-conflict`: the
  notify log carries `read position … changed outside Vox` where the assertion requires no
  notice: red, PRODUCT (the cursor itself is right either way; the assertion is the absent
  notice, which is what a person sees).
  *Act 2, claims between the decision and the held effect (F6, F9, R5).* Before the turn the
  agent holds `X` with a short ttl; the apparatus waits until the board shows `X` lapsed
  (`vox room board`), **then** the turn runs: its envelope reports `X` lost (`held_remove` holds
  `X`). The hook is a `test-knobs` build paused after the `decided` rename
  (`VOX_TEST_TURN_PAUSE_AFTER=decided`, as act 4; the local held effect is step 4 and runs after
  the pause, so this is the barrier before held application; APPARATUS if the pause is not
  observed). While paused, the agent's shell tool runs `vox room claim <room> X` (reacquisition
  of the same resource) and `vox room claim <room> Y`; the pause is released; later both lapse.
  Assert: the next turn after the lapses says `X` is no longer held and `Y` is no longer held,
  each once. Mutant A: apply `held_set` by overwrite instead of the stamped merge: `Y`'s lapse
  is never reported: red, PRODUCT. Mutant A2: merge by name without stamps (revision 1's rule):
  `X`'s second lapse is never reported: red, PRODUCT. v0.4.30: CANNOT MEASURE (knob absent;
  control above).
  *Act 3, the permanently gone room (F18, F7).* Hold a turn in room R2; the operator
  (apparatus, CLI) runs `vox room leave R2 --yes` while held; release `commit` with the daemon
  present (the prepare itself finishes: the obsolete receipt is found in the prepare's own
  finish, and its notice must reach the person through the **next** verb's structured answer).
  Assert: the notify log holds exactly one `Vox: room R2 is gone; a notice shown earlier there
  could not be marked delivered. Nothing in this conversation was lost.`; the next turn carries
  R1's news; no TJ-8 sentence. Variant: the apparatus closes the session's Session opening
  (`vox room sessions --end`, or the daemon's own close on a registration move) instead of
  leaving the room; assert the `Session opening there has ended` sentence and not the `gone`
  one. Mutant B: print the notice on stderr only (revision 1's design): the notify log lacks
  the line: red, PRODUCT. Mutant B2 (R7): the next prepare replaces the `done` journal without
  copying its notices into `carried[]`; that prepare is halted after its journal rename and
  before its envelope (`VOX_TEST_TURN_HALT_AFTER=prepared`): the notice is gone from disk and
  the notify log never gets the line: red, PRODUCT (the unmutated product prints it from
  `carried[]` in the following verb's answer).
  *Act 4, the hook killed after the decision (check-before-poison).* Staged with a
  `test-knobs` build of `vox` (the knob is compiled out of the installed release; v0.4.30:
  CANNOT MEASURE, control above):
  `VOX_TEST_TURN_PAUSE_AFTER=decided` makes the hook pause after the `decided` rename until the
  file named in `VOX_TEST_TURN_PAUSE_FILE` is removed. The shim releases `commit`; the
  apparatus SIGKILLs the paused prepare child (its own scratch pid) and removes the pause file.
  Assert: no TJ-8 sentence; `m1` delivered once; the next turn's news present. Mutant C:
  poison on an enveloped non-zero exit (`:262-264` restored): TJ-8's sentence appears:
  red, PRODUCT.
  *Act 5, the possibly shown turn with no decision (the decider's answer).* During the hold the
  apparatus kills the prepare child and then the shim itself (OMP dies mid-turn: its store holds
  a staged record for the turn and no accepted one), then starts the shim again on the same
  session store (RS-7's resume staging). Assert: the notify log holds the `uncertain` sentence
  exactly once; every later `--omp-prepare` of that session prints no envelope; `m1` is **not**
  delivered a second time in that conversation; a new conversation (a fresh session id on the
  same node) is registered and delivers `m1` once as unread news; `vox room sessions` shows the
  old Session open until it closes; after the apparatus kills and restarts the shim once more,
  the check and the next prepare still answer 78 (the tombstone, R2). Mutant E: skip the
  `publishing` rename (print the envelope from `prepared`): after the two deaths the next
  prepare finds `prepared`, cancels, and delivers `m1` again in the same conversation: red,
  PRODUCT (a second delivery where the assertion requires none). Mutant E2 (R2): write the
  tombstone after the archive move instead of before, and kill the hook between them
  (`VOX_TEST_TURN_HALT_AFTER=archive`, knob): the next prepare delivers `m1` again: red,
  PRODUCT. Variant (exactly-once with OMP alive): kill only the prepare child during the hold;
  assert TJ-8's sentence is absent and `m1` is delivered once (the extension supplies
  `commit` at `message_end`, TJ-3 "the hook died with OMP alive"). Mutant F: let the close
  handler call `finish(op,
  null)` for a dead enveloped child (`:271` restored): TJ-8's sentence appears: red,
  PRODUCT.
  *Act 6 (focused, `agent_hook_proof.rs`), the kill points.* `test-knobs` build only, the halt
  knob above. Staging: registration as `crates/vox-tui/tests/support/omp_bridge_replay.py:
  425-451` does it (`vox agent omp-watch` owner, `--attention-register`,
  `--omp-check-uncertainty` with the extension's environment); then `--omp-prepare` directly
  with `commit` or `cancel` on stdin, the halt at each step in turn, then `--omp-finish` until
  it answers 0 or 78, then a plain prepare. Assert from the hook's output (what the model would
  see) and its structured line: for `spawned`, `admitted`, `prepared` and `prepare-sent`, the
  next prepare's envelope carries `m1` (shown once, later); for `publishing`, `--omp-finish`
  answers `undecided`, the next prepare answers 78 and prints no envelope, and a prepare for a
  fresh session id carries `m1` once (row 36, asserted); for `tombstone` and `archive`, every
  later verb answers 78; for every later effect step, `--omp-finish` answers 0 with no notices
  and the next envelope carries `m2` (posted between the abort and the finish) and not `m1`;
  the offer once; the lost claim once. Control on v0.4.30 (no halt): `commit` shows `m1` once
  and a second prepare does not; `cancel` shows `m1` again. Mutant D fails the `cursor:<room>`
  step on its "no notices" assertion. Mutant G (cancel applies the cursor step, revision 1's
  defect, F2): a `publishing` halt resolved with `--omp-finish --decided cancel`; the next
  envelope lacks `m1`: red, PRODUCT.
  *Act 7, cancel before injection and the admitted attempt (F2, F3, R6).* An
  attention-triggered turn (the daemon dispatches a notice; the shim's turn carries
  `VOX_OMP_NOTICE`); the prepare child is paused by `VOX_TEST_TURN_PAUSE_AFTER=prepare-sent`
  before its envelope; the shim raises `session_before_switch` and `session_switch`:
  P420-OR-6's retire runs with an operation that is not injected, and the extension itself
  sends `cancel` (`:799`, `finish(operation, "cancel")`). Assert: no provider request payload
  contained the operation's marker (the shim logs every payload); within 30 s and without a
  prompt from the person the daemon dispatches a new wake for the same notice on the new
  generation (the shim logs `sendMessage`), and the turn that wake starts delivers the notice
  once. The apparatus removes the pause file as soon as the shim has logged the retire's
  `cancel`, identically with and without the mutant; a cancel not logged within 10 s is
  APPARATUS, not a red. Mutant H: skip `Dispatch(Held)` on cancel: no second wake within 60 s
  after the release: red, PRODUCT (no manual turn is run first, so the attempt's release is
  the only thing that can produce the wake). v0.4.30: CANNOT MEASURE (knob absent); the
  knob-free control (the same switch with no notice in flight shows no Vox line) is green
  there.
  *Act 8, the model step that ends in an error (TJ-3 (iii); row 79).* Sub-acts through the
  real extension, the shim ending the step as OMP does (`message_end` with an assistant message
  whose `stopReason` is `error` or unknown):
  (8a) a terminal error after injection: one `before_provider_request` carrying the marker,
  `tools` present (an ordinary agent request); the step ends with an empty error message.
  Assert: the sentence of TJ-8 once; the extension injects nothing in later turns of that
  conversation; ordinary turns continue (the shim's prompt turns end); `m1` is not delivered
  in that conversation; a fresh session on the same node delivers `m1` once; the check answers
  78 after a shim restart. Mutant I: treat the errored step as committed (any of the withdrawn
  "delivered after an error" rules): no sentence and `m1` counted delivered by the oracle in a
  later step: red, PRODUCT. Mutant I2: cancel on the error (offer again): TJ-8's sentence is
  missing, and a later staged record of that conversation carries `m1` as news (a later
  insertion in a conversation TJ-3 (iii) made uncertain): red, PRODUCT on both; the oracle's
  post-commit second-insertion rule does not catch it, since the first identity never
  committed.
  (8b) an error after injection with no request built (a credential failure): no
  `before_provider_request`, an empty error message. Assert as 8a. Mutant J: cancel on "no
  callback fired" (revision 4's rule): no sentence: red, PRODUCT.
  (8b′) not injected: the hook is halted after `publishing` and before it prints
  (`VOX_TEST_TURN_HALT_AFTER=publishing`; the extension parses no envelope line). Assert: no
  sentence; `m1` delivered once, in a later turn. Mutant J3: classify `!enveloped` as uncertain:
  the sentence appears: red, PRODUCT. v0.4.30: CANNOT MEASURE (knob absent); the knob-free
  control (a prepare that prints and commits) is green there.
  (8c) two `before_provider_request` events in one step, then an error. Assert as 8a. Mutant K:
  treat the step as committed: no sentence: red, PRODUCT.
  (8d) a payload that does not contain the marker (blob-style), `api: cursor`, then an error.
  Assert as 8a. Mutant J2: cancel on `!op.matched`: no sentence: red, PRODUCT.
  (8e) a callback-less transport: no `before_provider_request`, then a `message_start`/
  `message_end` pair with an empty gateway error. Assert as 8a. Mutant J covers it.
  (8f) OMP's automatic step replay after an error: the shim ends the step with an error
  `message_end` (as OMP forwards it, `agent-session.ts:4768-4769`), then, as OMP's `agent_end`
  maintenance would, starts a replayed step. Assert: TJ-8's sentence once, at the error; the
  replayed step's `context` gets nothing injected; `m1` is not delivered in that conversation;
  a fresh session delivers it once. (8f′) a provider-attempt retry: the shim emits
  `before_provider_request` twice for one step with no `message_end` between them (OMP's
  `withReplaySafeStreamRetry` calling `onPayload` again) and then ends the step with
  `stopReason: stop`. Both builds carried the marker and the step completed, so the delivery
  oracle counts one delivery here whether or not Vox commits; this sub-act therefore does
  **not** assert a delivery count. Assert instead: TJ-8's sentence once; no
  `vox-context-accepted` record for the operation and no `--omp-finish --decided commit` call
  for its record (the shim logs both); no later `context` event of that conversation gets Vox
  news injected (the shim's inserted-message log stays empty for Vox after the sentence). A
  fresh session's delivery of `m1` is the warned re-delivery of TJ-8 and is observed apart from
  the exactly-once oracle. (The one-build rule, TJ-3 (i); the shipped extension already rules
  this way, so 8f′ is a guard against relaxing it.) Mutant Q: treat two builds with no message
  between them as one request and commit: TJ-8's sentence is absent and an accepted record and
  a commit call appear: red, PRODUCT on the first two assertions. (8f″) the invisible HTTP
  retry: one `before_provider_request`, then the shim's provider answers a 429 once and succeeds
  on the transport's own retry below the payload callback (OMP 18.20.0: `onPayload` at
  `openai-completions.ts:952`, before `options.fetch` → `fetchWithRetry`, `:983-1000`; no second
  `onPayload`, no `message_end` for the 429), then the step ends with `stopReason: stop`. The
  E-30 shim has no fetch implementation today: a fetch stub **is to be written** for this
  sub-act, returning a retryable 429 once and then valid SSE ending in `stop`. Assert: no
  sentence; `m1` delivered once; exactly one `before_provider_request` was logged. This is the
  only retry that changes nothing.
  *Act 9, the hook killed after admission (R1).* An attention-triggered turn; a `test-knobs`
  hook halted after `Admit` and before the `prepared` journal (`VOX_TEST_TURN_HALT_AFTER=
  admitted`). Assert: within 30 s and without a prompt from the person a new wake arrives for
  the same notice (the shim logs `sendMessage`), and the turn it starts delivers the notice
  once. Mutant L: write the `admitting` journal after `Admit` instead of before: no second wake
  within 60 s: red, PRODUCT. v0.4.30: CANNOT MEASURE (knob absent; control above).
  *Act 9b, the hook killed before its first write (third review finding 3; K0).* An
  attention-triggered turn; the prepare child halted by `VOX_TEST_TURN_HALT_AFTER=spawned`
  (abort after start, before any file write; one staging, task cut 9). Assert: without a
  prompt from the person, within 30 s a new wake arrives for the same notice and its turn
  delivers it once (the extension's `--omp-release-notice` released the accepted attempt).
  Mutant M: drop the `--omp-release-notice` call from the close handler: no second wake within
  60 s; the person's next prompt turn then delivers the notice (today's behavior): red,
  PRODUCT on the 60 s assertion. v0.4.30: CANNOT MEASURE (knob absent); the control (an
  attention-triggered turn not killed delivers its notice once with no prompt) is green there.
  *Act 10, retirement across an outage with the old conversation open (third review 4; fourth
  review P2; fifth review P2; task cut 13).* Staged **with the extension alive**: an
  **attention-triggered** step (the shim's turn carries `VOX_OMP_NOTICE`, so the old Session
  holds a notice and an attempt), ambiguous as 8c; the daemon is stopped by the apparatus (its
  own scratch pid) after the envelope and before the step ends; the extension classifies (c)
  and calls `--omp-finish --uncertain`, which writes the tombstone and answers 78 with
  `retired: false` (no daemon); the shim logs that answer (a staging premise: if it is not
  logged the act is APPARATUS); 20 s later the apparatus starts the daemon again; the old
  conversation stays open, no prompt is typed, no new conversation is started, and the
  extension's watcher is left alone (its `ready` frame will come). Assert: within 30 s of the
  daemon's return `vox room sessions --json` shows the old Session's notice `delivered` and the
  daemon's `Pending` page for it empty. Mutant N mutates **both** continuation routes (fifth
  review P2): the ladder stops at 78 regardless of `retired`, and the watcher-`ready` restart
  of `finishPending` is removed; the attempt stays pending until the old conversation is
  closed: red, PRODUCT. v0.4.30: CANNOT MEASURE (no `--omp-finish`, no `retired`).
  *Act 11 (focused, `agent_hook_proof.rs`), the other harnesses' reservation (TJ-9; task cut
  17; sixth review P2).* A Claude-shape hook (no `--omp-prepare`, `VOX_HARNESS=claude`) halted
  after `Prepare` (`VOX_TEST_TURN_HALT_AFTER=prepare-sent`); then the next hook of the same
  session, which cancels from the ticket file; then the apparatus posts a distinct `m2` and
  waits for the daemon's notice for that session (the Claude adapter's delivery to the
  apparatus's registered route, logged by the apparatus as the adapter's call), without
  draining anything by hand. Assert: the recovery hook's envelope carries `m1` once (it
  cancelled the ticket and drained); the adapter delivered the notice for `m2` within 30 s; the
  hook that consumes that notice carries `m2` once and not `m1` again. `Resolve`'s
  `notice_pending` is not evidence (it is true for a leaked reservation too, `ledger.rs:
  330-332`). Mutant O: skip the ticket file: no adapter delivery within 60 s: red, PRODUCT.
  An unavailable route is APPARATUS. v0.4.30: CANNOT MEASURE (knob absent); the knob-free
  control (a hook that is not killed; the next notice arrives) is green there.
  *Act 12, two verbs at once (TJ-5, TJ-6; task cut 18; sixth review P2).* Through the real
  extension: while a prepare is held between the envelope and `commit` (act 1's hold), the
  apparatus runs `vox agent hook --session <id> --omp-finish` from the shell. Assert: that verb
  exits 75 with `Vox OMP preparation is busy`; the held turn still commits and delivers `m1`
  once; no second envelope appears in the notify or context log. Mutant P: take no session lock
  in `--omp-finish`: the verb exits 0 instead of 75 (it answers `undecided` for the live
  journal): red, PRODUCT on the missing 75. v0.4.30: CANNOT MEASURE (no `--omp-finish`); the
  knob-free control (a second `--omp-prepare` during the hold exits 75, `agent_hook.rs:
  291-295`) is green there.
  Acceptance TJ-10-A: twenty held commits through restarts (ADR-045 J7(b)) with zero `uncertain`
  lines and every message delivered once. Every act stages with scratch processes, files, the
  shim's own events and `test-knobs` builds; none needs the host (ruling 32); acts 1 and 10
  treat a daemon they did not start as APPARATUS.

## Unchanged rulings

- ADR-029 P420-OR-6, whole, including "Any delivery Vox cannot classify keeps the per-Session
  uncertainty marker, never cleared or replayed" (the decider, 2026-11-13): the uncertain
  journal is that marker.
- ADR-018: no unit tests; proofs drive the shipped binary; every proof has a mutant; knobs only
  behind `test-knobs`.
- ADR-021 M21.9 and V210-79: a claim is recorded when it is made; a lapse is told once.
- ADR-028 RR-1: read marks are best effort for the members' `read by`; a room that refuses them
  permanently costs the members a mark, never the turn.
- ADR-040 NW-3's "not parked here": the journal is its own durable store; the hook's wait on a
  `NotYet` is bounded by its deadline and then owned by the extension.
- ADR-041 RS-7's proof file is the one justified new file for the extension; this ADR adds acts,
  not a file.
- Session steps are kept two days (ruling 49, ADR-047); nothing here depends on that bound.

## Superseded and amended lines

Main applies these. Quotes are from the tree at `d9a8667ba`, the whole sentence, with the
physical line break joined.

| Line | Was | Is to be |
|---|---|---|
| ADR-029 P420-OR-6 | "Any delivery Vox cannot classify keeps the per-Session uncertainty marker, never cleared or replayed." (`docs/adr/ADR-029-sessions-and-the-repo-room.md:486-487`, one sentence over two lines; the physical line 486 begins "A prompt the person submits inside OMP's own generation/identity gap is an OMP-native race outside Vox's control; Vox content is excluded from it. Any delivery") | **Unchanged** (the decider's answer). Reading note, not an amendment: the marker is the `uncertain` turn journal (ADR-050 TJ-8); a turn with a decision is not "a delivery Vox cannot classify" and is finished (TJ-4). |

Rows that this ADR's revisions 1–5 listed here for ADR-040 r2 NW-10, ADR-041 RS-7 (twice),
ADR-041 "Changes this revision asks of siblings" and ADR-042's ADR-050 bullet are not
amendments: none of those files exists at `d9a8667ba` (`adr-amendment-quotes`, ADR-050 rows
2–6, NOT FOUND / NO QUOTE). They are sibling contracts of this release and stand below, with
their targets' current worktree lines.

### What sibling ADRs must change or keep (contracts, by id)

- **ADR-040 NW-1, NW-3 (r10, D11).** ADR-040 owns both ends of the hook's `wait_ms` request
  (the daemon holds the request up to `wait_ms`; the hook sends it, `agent_hook.rs:408-418`);
  this ADR keeps them as a contract and owns only what happens after the answer: a typed
  `NotYet` after the decision is waited for inside the hook's own 5 s and then becomes 79
  (TJ-6). Nothing here changes `wait_ms`. **NW-8**: unchanged; the pre-envelope refusal stays
  the extension's retry.
- **ADR-041 RS-7, RS-9.** RS-7 (ADR-041 r8, frozen `ADR-041.01cad8419.md`) hosts this ADR's
  shim duties and says "acts 1–10". **Final list for v0.4.31**: RS-7's file hosts acts 1, 2, 3,
  4, 5, 7, 8 (8a–8f), 9, 9b, 10 and 12; `agent_hook_proof.rs` hosts acts 6 and 11. Host duties
  that remain (paste text): the shim MUST (1) log every `appendEntry` of `vox-context-staged`
  and `vox-context-accepted` with its `id`, `marker` and content; (2) log every
  `before_provider_request` payload so a marker's presence can be counted per step, and be
  able to emit zero, one or two such events in one step, and one whose payload omits the
  marker; (3) end a step with an assistant message carrying `stopReason: error` or an unknown
  stop reason, log every `message_end` with its `stopReason` and `errorMessage`, and be able
  to run, after an error `message_end`, a replayed step as OMP's `agent_end` maintenance does
  (the error is forwarded to the extension first); to emit two `before_provider_request`
  events for one step with no `message_end` between them (a provider-attempt retry that calls
  `onPayload` again); and to answer one request with a transport-level 429 that its own fetch
  stub retries below the single payload callback (one `before_provider_request`, no error
  `message_end`); (4) raise
  `session_before_switch` and `session_switch` during a prepare, and `session_shutdown`; (5)
  keep a session store with `getEntries`/`getBranch`/`appendEntry`/`ensureOnDisk`/
  `getSessionFile` under OMP's persistence rules for RS-9's own cases (no ADR-050 act calls
  `ensureOnDisk`); (6) be killable and restartable on the same session file; (7) hold an aside
  turn that injected content between the envelope and the model's answer while an arm file
  exists (E-30's `shim-hold.mjs`); (8) log `sendMessage` (wakes), `ui.notify`, `ctx.abort` and
  each `context` result's inserted messages. **No longer needed** (revisions 6–7): payload
  `tools` shapes (absent / client tool / hosted tool), `message_update` with `toolcall_start`,
  re-placement logging, reparenting or `/clear` of the branch, a latched append failure the
  apparatus can set. Acts by need: 1 (7, 1, 8); 2, 4 (pause knob; 8); 3 (1, 8); 5 (6, 1); 7 (4,
  2, 8); 8a–8f (2, 3, 8); 9, 9b (knob; 8); 10 (2, 8; the daemon stopped mid-step); 12 (7, 8).
  **RS-12**: no new IPC request from this ADR. **RS-2**: act 1's "daemon absent for 5 s" is
  apparatus, not a claim about the restart's length.
- **ADR-042 TR-11.** TJ-6's stderr line and TJ-7's three sentences follow TR-11 (carried,
  `ADR-042-status-reports-outcome.md:1302-1303, 1440`: "the hook's refusal texts follow
  TR-11"). The agent-invocation act this ADR hosted for TR-13 is withdrawn (ADR-042 r9, ruling
  Q1, ledger row 22; cross-asks L1-16, X050-7, X042-15).
- **ADR-045 J7(b), ruling 32.** Acceptance TJ-10-A is its row 30 (carried, `ADR-045:777`;
  `:746` still cites "ADR-050 r1": cite the current ADR); every act here is staged with
  scratch processes and files and runs inside the guest or the Linux VM.
- **ADR-049 LE-4.** **Change asked of ADR-049** (cross-asks X050-10): LE-4's erasure steps
  name the hook's per-session files of the room, `cursors/<room>-<session>`, `held/`,
  `pulling/`, `pulling-scan/`, `joined/` (v0.4.30's `remove_room_cursors`, `paths.rs:688-709`,
  deletes only the first two), so that TJ-4 step 3's "file absent and room not held →
  obsolete" holds for every file `apply` touches; and the daemon's room list (`client.rooms()`)
  omits a room from the moment its erasure begins, which TJ-4 step 3 reads as "not held".
- **ADR-047.** No format of the node store changes; the journal is a private file under
  `cursors/`. The held file's stamped lines, its lock file and `tickets/` are new small files
  under `cursors/`. Ruling 49 (Session steps two days) touches nothing here.
- **ADR-048.** None (cross-asks X050-12: consistent; a daemon egress parks on
  `TrustDebt(room)`). A trust debt that refuses a receipt or read mark is a `NotYet` (TJ-4
  steps 5–6) and the ladder waits; it never poisons.
- **ADR-040 NW-9** (cross-asks X040-24): carried in TJ-5's registration row. **NW-1/NW-3/NW-8**
  (X040-23, X050-1): carried in TJ-6's hook side, both branches.
- **ADR-029 P420-OR-6.** Unamended. Its "acceptance only at the assistant's `message_end` with
  one request, one marker and a known stop reason" is TJ-3 (i), and its "never cleared or
  replayed" is TJ-3 (iii).

## Implementation order and related work

1. TJ-2, TJ-4 (journal with states, `apply`, stamped held merge and lock, the cancel path),
   TJ-5's lock in every `drain`.
2. TJ-6 hook side (79, `--omp-finish`, `--omp-check-uncertainty` finishes first, the envelope's
   `turn` field), TJ-8's triage.
3. TJ-3 and TJ-6 extension side (`VOX_OMP_RECORD`, `finishPending`, the decoders, the close
   handler), TJ-7.
4. TJ-9's ticket file for the other harnesses.
5. TJ-10's acts in RS-7's file and `agent_hook_proof.rs`; the
   amendments above.

Needs: ADR-040 NW-1's typed attention answer (for the wait; without it the hook treats every
refusal after the decision as "not yet, 79", which is safe but waits on permanent refusals too:
acceptable for landing order, not for release). Other lanes: ADR-041 RS-7's file and shim;
ADR-042 TR-11's wording review of the three sentences; ADR-045 J7(b).

## Consequences

### Positive

- A committed turn always finishes; no conversation is replaced because the daemon was busy or
  restarting at the wrong moment. The operator's repeated session replacement of 2026-11-12
  ends.
- The guarantee is stated per window: exactly-once with a decision; shown later once when
  nothing was injected; uncertain for good otherwise; never a repeat by Vox's doing.
- A reservation or an admitted attempt never dangles; a claim made while a turn finishes, even
  of the resource just reported lost, is never lost.

### Negative

- Three durable renames per OMP turn instead of one write and one remove (a few milliseconds
  on the Mac; invisible against the model's step).
- The decider's answers keep the dead-conversation cases TJ-8 lists: every terminal provider
  error or unknown stop reason after an envelope, on every transport; a switch, update or
  shutdown mid-step; OMP dying mid-step; a corrupt journal. Each is today's case and costs a
  new conversation, which is then shown the room's unread news again. Ordinary chat and tools
  in the old conversation continue.
- A new hook exit code (79), three new flags, a structured stdout line and an envelope field:
  hook surface that the v0.4.31 extension and binary ship together (v0.4.x has no prior-release
  compatibility requirement; an older extension with a newer hook poisons on 79 as it poisons
  on 1 today). The held file's format changes.

### Neutral

- The journal, the held lock, the stamped held lines and the ticket file are private files
  under `cursors/`; no store or wire format changes. The `omp-uncertain/` directory is gone.

## Links

- ADR-018, ADR-021, ADR-028, ADR-029, ADR-040 (r3), ADR-041, ADR-042, ADR-045, ADR-049.
- Reviews: `adr-040-sol-review.md` (findings 3, 4, 5, 14, 15, Q2/Q6),
  `adr-040-sol-review-2.md` (F9, F17, F18, "OMP crash-window and consumer assessment",
  final question 2), `adr-050-sol-review.md` (F1–F10).
- Revision note: `adr-050-revision.md`.
- Fix list item 30; plan D §30; RcaTrust T2; cross-ADR ledger rows 32, 36, 49.
- Experiments: `/opt/vox-evidence/v0431/adr050/` (E-30's rig, shim and receipts of runs
  `e` and `f`); RcaTrust's runs `s3`, `c1`, `c2`, `w1` are recorded in `rca-RcaTrust.md`
  (their receipts under `/tmp` were lost in the reboot of 2026-11-13).

## Crash windows: every kill point

K = kill the hook, the daemon, or OMP at that point. States are TJ-2's; steps TJ-4's. The last
column is the classification of TJ-1: **once** (exactly-once), **later** (provably not shown;
shown later, once), **uncertain** (possibly shown; the conversation is done with Vox).

| # | Kill point | State on disk | Next verb does | Class |
|---|---|---|---|---|
| K0 | after the extension accepted the notice and spawned the prepare, before the hook's first write (`admitting`, now written before the `Resolve`) | nothing on disk; an accepted, unadmitted attempt in the ledger with no expiry (`ledger.rs:627-634, 732-735`) | the extension's close handler (non-enveloped exit of an attention record) runs `--omp-release-notice` on the ladder: `Resolve` + `Dispatch(Held)`; the daemon dispatches again. If OMP died too: the person's next prompt turn drains the sources (`reconcile_attempt`), as today | later (extension-owned; third review finding 3) |
| K1 | after `Admit`, before the `prepared` journal | `admitting`; attempt admitted | cancel path: `Dispatch(Held)` releases the attempt; remove; the daemon dispatches again (R1) | later |
| K2 | after the `prepared` journal, before `Prepare` | `prepared`; tickets unused | cancel path (no-ops), remove, prepare afresh | later |
| K3 | after `Prepare`, before the `publishing` rename (includes the 30 s watchdog) | `prepared`; tickets pending, attempt admitted | cancel by exact recipient and ticket; `Dispatch(Held)` releases the attempt; remove; the daemon dispatches to the session again (F3) | later |
| K4a | after `publishing`, before any byte is printed, or after a partial line | `publishing` | extension alive: `!enveloped` → supplies `cancel` (TJ-3 (ii)); OMP dead too: uncertain (conservative; the rename-to-output interval is not bounded under suspension) | later / uncertain |
| K4b | after the whole envelope line, before the decision line is read (the model's whole step) | `publishing` | extension alive: the step's end is classified (TJ-3 (i)–(iii): commit, cancel, or uncertain); OMP dead too: on resume an accepted record → `commit`, else uncertain | once / uncertain |
| K5 | after the line is read, before the `decided` rename | `publishing` | as K4b (the extension holds the decision it wrote) | once / uncertain if OMP also died with no accepted record |
| K6 | after `decided`, before any effect | `decided` | `finish_turn` from step 1, or the cancel path | once |
| K7 | after any one local effect (markers, offers, pulling, cursor, held), before the next | `decided`; that file replaced | the replaced file equals its outcome → done; the rest applied | once (Mutant D fails here) |
| K8 | daemon dies during `Received`, after applying it or before | `decided`; ticket consumed or not | `Received` again with the exact recipient: consumed → no-op; not → applied | once |
| K9 | daemon dies during `MarkRead` | `decided`; marks partly put | `MarkRead` again: `was_read` skips | once |
| K10 | after every step, before `done` | `decided`, all applied | every step finds its outcome; `done` | once |
| K11 | after `done` with notices, before a verb delivers them | `done` with `notices[]` | `--omp-finish`/check print them, then remove; a prepare copies them into its journal's `carried[]` in the rename that replaces the `done` journal, prints them in its envelope, and drops them at `decided` (R7) | once; the notice is shown once (deduplicated by id) |
| K11b | a prepare dies after replacing the `done` journal and before its envelope | `prepared` with `carried[]` | cancel path keeps `carried[]` as a `done` journal; the next verb prints them | once |
| K12 | OMP dies after a verb printed the notices and removed the journal, before `notify` | nothing | nothing | once; that notice is lost; nothing in the conversation is lost |
| K13 | a new message arrives between the journal and the cursor effect | the message is not in `cursor_to`/`ahead_add` | finishing applies the journaled cursor; the message is unread and shown next turn | nothing swallowed |
| K14 | a claim or a reacquisition is made between the decision and the held effect | the held file holds the new stamped line | the stamped merge keeps every line stamped at or after `selected_at` | the claim's later lapse is told |
| K15 | the room is left or ended, or the Session opening closed or replaced, between the decision and the effects | cursor and held files gone and/or the opening changed | cursor: obsolete; receipt: obsolete (room gone / opening ended), one notice (TJ-7) | nothing invented; conversation usable |
| K16 | two verbs at once | one holds the lock | the other: 75, retried on its ladder | one envelope at most |
| K17 | cancel path interrupted after some `CancelPrepared`, before `Dispatch(Held)` or removal | `decided: cancel`; some tickets cleared | the cancel path again: cleared tickets are no-ops; `Dispatch(Held)` on a missing attempt is a no-op; remove | later (the cancelled news is offered again, once) |
| K18 | the journal file is unreadable | bytes | tombstone first, then the move to `archive/`; 78 | uncertain (disk corruption, not a crash window) |
| K19 | after the tombstone, before the retirement requests or the archive move | tombstone (`retired: false`), journal | every verb: 78; the retirement is retried from the archived or still-present journal until the daemon accepts it | uncertain; nothing requeued |
| K20 | a live model step ends in an error or an unknown stop reason after injection, as seen by the extension at `message_end` | `publishing` | TJ-3 (iii): uncertain, on every transport, whether or not OMP replays the step afterwards; a provider-attempt retry (second `before_provider_request`) is uncertain too; only an HTTP retry below the one payload callback is invisible and not an end | uncertain |
| K21 | OMP exits, the conversation is switched away, or an update succeeds while a turn is unresolved | `publishing`; no accepted record | retire (`:799`) resolves it uncertain; `register()` after a restart without an accepted record on the branch: uncertain | uncertain |

Provably not shown, replay allowed: K0, K1, K2, K3, K4a with the extension alive, K17.
Uncertain for good: K4a with OMP dead, K4b and K5 with OMP dead and no accepted record, K18,
K19, K20, K21, and the events TJ-8 lists. Everything else is exactly-once.

## Review record

Each finding of the three reviews in this lane, its classification after checking the
`v0.4.30` tree and revision 1's text, and the requirement that answers it.

| # | Finding | Classification (evidence) | Answered by |
|---|---|---|---|
| ADR-040 1st-3 | The journal records the decision, not the turn's effects | CONFIRMED (`agent_hook.rs:319-335`; `RoomDrain::commit` `:2976-3023`; `shown_in` `:3366-3393` known before emission) | TJ-2 (every effect, the complete recipients, before `Prepare`); TJ-4 never re-selects; K13 |
| ADR-040 1st-4 | Cursor commits are not replay-idempotent | CONFIRMED (`merge` `:725-732`) | TJ-4 step 3; Mutant D |
| ADR-040 1st-5 | The new exit code has no consumer; the watchdog case poisons | CONFIRMED (`:355`, `:507`, `:345`, `:262-264`; the prepare watchdog `:244` is cleared at the envelope `:287`, so the 30 s kill is `hook()`'s `:328`, which covers `--omp-finish`) | TJ-6; TJ-10 act 4, Mutant C |
| ADR-040 1st-14 (OMP part) | Proof placement; internal assertions; unreachable mutants | CONFIRMED (RS-7 `:795-796`; a restart during the hold fails at `check_omp_opening` before any cursor write) | TJ-10: RS-7's file; conversation-visible assertions; act 1's 5 s absence reaches Mutant D; act 6 is a declared baseline |
| ADR-040 1st-15 (OMP part) | `run-s3` is instrumented; E-30 unrun | CONFIRMED; **closed by E-30 run `f`**, whose own verdict line is `VERDICT: PRODUCT red …` (`/opt/vox-evidence/v0431/adr050/f/timeline.log:61`) | "Evidence status" quotes the verdict and the sequence; act 1 cites it |
| ADR-040 1st Q2/Q6 | Uncertain delivery (A/B); decided-turn identity loss | Q2 answered by the decider (A); Q6 engineering | "The decider's answer"; TJ-7 |
| ADR-040 2nd-F9 | Claim commands outside the writer/merge protocol | CONFIRMED (`room_cli.rs:3814-3818`, `:3456-3458` → `note_held` `:962-969`, no lock) | TJ-5; TJ-4 step 4 (stamped merge under the held lock); act 2 |
| ADR-040 2nd-F17 | The oracle counts historical context | CONFIRMED (`:1127-1147`, `:1176-1190`; `run-c1.out` one nonce 32 times) | TJ-10's oracle (first staged record, correlated with the request marker and the accepted record) |
| ADR-040 2nd-F18 | The obsolete-receipt notice goes to a discarded stderr | CONFIRMED (`:335-336`, `:243`) | TJ-7; act 3 |
| ADR-040 2nd crash-window rows 1–12 | — | agreed, with row 2 and row 3 narrowed by the states of TJ-2 and the extension's own record (TJ-3) | K1–K18 |
| ADR-040 2nd `mark_read` | journal the exact list | CONFIRMED (`:3772-3776`; `read.rs:166-168` idempotent) | TJ-2 `mark_read[]`; TJ-4 step 6 |
| ADR-050 F1 | Persist the complete attention recipient | CONFIRMED (`attention.rs:101-112` has `opening`, `identity`; `channel/attention.rs:103-107` rejects a differing recipient with `attention selection changed`; `ledger.rs:276-298` keys by `identity`; revision 1's `receipts[]` had neither) | TJ-2 `receipts[].recipient` complete; TJ-4 step 5 (the two obsolete kinds; no replacement `Resolve`) |
| ADR-050 F2 | Cancellation ran the commit effects and read marks | CONFIRMED (revision 1's TJ-4 changed only step 5 for `cancel`; v0.4.30 cancels and returns, `:3585-3594`) | TJ-4 "Cancel"; act 6 Mutant G; act 7 |
| ADR-050 F3 | Cancelling must release the admitted attempt | CONFIRMED (`ledger.rs:672` sets the attempt; `:698-707` admits; `:790-821` clears tickets only; `:627` refuses `begin` while an attempt exists; cleared only by `dispatch` `:709-748` or `reconcile_attempt` `:967-976`) | TJ-2 `notice`; TJ-4 cancel path `Dispatch(Held)`; TJ-8 `prepared`; act 7, Mutant H |
| ADR-050 F4 | Unconfirmed emission must be treated as possibly shown; absent native records prove nothing | CONFIRMED (revision 1's K4 replayed after a flushed envelope with `emitted:false`; `omp-extension.ts:1231-1235` proceeds from `appendEntry` to injection; ADR-041 RS-9 on swallowed appends) | TJ-2 `publishing` before any byte; TJ-3 steps 3–5 (only `!enveloped` and an accepted record are evidence); TJ-8; K4a/K4b |
| ADR-050 F5 | The repeat notice was written after the journal was removed | CONFIRMED on revision 1's text; moot under the decider's answer | TJ-8 *Deleted* |
| ADR-050 F6 | A reacquired claim of the same resource is deleted by replay | CONFIRMED (`note_held` records names only, `:962-969`, and writes nothing when the name is present; revision 1's `(current − held_remove) ∪ held_set` removed it) | TJ-4 step 4 (stamped lines; `≥ selected_at` kept); TJ-5; act 2 (`X` reacquired), Mutant A2 |
| ADR-050 F7 | Outcomes must be delivered from a successful prepare too; distinguish opening ended from room gone | CONFIRMED (revision 1 routed notices through `--omp-finish` only; a prepare that finishes by itself exits 0 with its envelope already consumed) | TJ-6 (`notices[]` in every structured answer and in the envelope's `turn` field; `done` retained until delivered); TJ-7 (three sentences, ids); act 3 variant, Mutant B2; K11 |
| ADR-050 F8 | A damaged journal must not abandon its reservations | CONFIRMED (revision 1 answered 0 after moving the file; the ledger could still hold `outputs_pending` and an attempt) | TJ-8 (unreadable → `uncertain`, never 0; the Session's close releases the ledger's side); K18 |
| ADR-050 F9 | The other harnesses' guarantee was overstated | CONFIRMED (`opencode-plugin.js:974-1002`: injection after `runHook` returns; the hook's cursor and `Received` already done) | TJ-9 and Context "What the other harnesses do" (acknowledge output; may repeat; may skip) |
| ADR-050 F10 | Impossible staging (act 4's lock), masked mutants (D, E), an `emitted` abort contradicting exactly-one envelope, the oracle not tied to a request | CONFIRMED (the prepare holds the session lock through its decision, `:370`; Mutant E was recoverable through TJ-3; a conflict leaves the cursor correct) | TJ-10: act 4 by a `test-knobs` pause knob (declared baseline); act 2 by a daemon hold; Mutant D asserts the absent notice; Mutant E skips `publishing`; act 6's `publishing` step asserts 78 and the fresh-session delivery; the oracle correlates staged record, request marker and acceptance |
| ADR-050 final question | A or B | answered by the decider: A | "The decider's answer" |
| ADR-050 2nd R1 | Admission precedes the journal | CONFIRMED (`omp_prepare` runs `Resolve` and `Admit` at `:408-461` before `drain`; revision 2's journal was written at `:3413`, inside `drain`) | TJ-2 `admitting` state before `Admit`; TJ-4 cancel path on it; K1; act 9, Mutant L |
| ADR-050 2nd R2 | An unreadable journal was archived with no durable terminal record | CONFIRMED on revision 2's text | TJ-8 tombstone written first, `archive/` after; every verb checks the tombstone first; K18, K19; act 5's shim-restart assertion, Mutant E2 |
| ADR-050 2nd R3 | A completed step with no decision reached no branch; `:206` kept; "two deaths" was false | CONFIRMED (`finish(op, null)` at `:1282`, `:1245`, `:459`, `:799`, `:1349`; `:206` poisons; `op.done = true` with no decision matched no branch of revision 2's close handler); the trace of the installed OMP is in Context | TJ-3 steps 2–4 and its classification (a)/(b)/(c) by the facts; TJ-8's list of events; Q7; act 8, Mutants I, J, K; K20 |
| ADR-050 2nd R4 | A new conversation does not close the old Session; its attention stayed pending | CONFIRMED (ADR-041 RS-8 keeps live registrations; revision 2 relied on the close) | TJ-8 "Retiring the Session's attention": `Received` for the journaled receipts (consumed, never requeued), `Dispatch(Held)` for the attempt, `retired` flag retried by every later verb, owner named; the Session close as the fallback |
| ADR-050 2nd R5 | Act 2 could not stage: X lapsed after selection; daemon absence does not hold the local held effect | CONFIRMED (TJ-4 step 4 runs before step 5) | act 2 restaged: lapse before selection; the `decided` pause knob as the barrier; A and A2 fail distinct assertions |
| ADR-050 2nd R6 | Act 7 substituted `cancel` for a model error, bypassing the consumer | CONFIRMED (an errored step runs `finish(op, null)`, never `cancel`) | act 7 restaged on P420-OR-6's retire route (`:799`) before injection; marker absent from every payload; the automatic wake is the assertion; H fails it |
| ADR-050 2nd R7 | The single journal is replaced before the old notices are delivered; B2 was not red | CONFIRMED (one file per session; a prepare's journal rename replaces the `done` one) | TJ-2 `carried[]` copied in the replacing rename, delivered in the envelope, dropped at `decided`; cancel keeps it as `done`; K11, K11b; Mutant B2 replaced |
| ADR-050 2nd, K4b partial line | should take `!enveloped → cancel → later` explicitly | agreed | K4a now covers the partial line; TJ-3 step 2 |
| ADR-050 2nd, E-30 | run `b` is APPARATUS, not the owed red | CONFIRMED (no news reached the held turn; see "Experiments") | measured by run `f`; runs `b`–`e` APPARATUS in "Experiments" |
| ADR-050 3rd-1 | `!op.matched` is not non-exposure evidence (blob-backed providers); cancel before ambiguity | CONFIRMED (`packages/ai/src/providers/cursor.ts:6631-6688` history as blobs, `:7220-7245` `onPayload` on the blob-referenced request, `:2515-2541` blobs served during the request; the extension's `markerCount` searches the payload only, `:297-315`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 3rd-2 | a staged entry's readback proves neither durable acceptance nor inclusion in the next request | CONFIRMED (`session-manager.ts:1954-1988, 2158-2178` memory-first, non-throwing; `turn-recovery.ts:1404-1437` reparents past the failed assistant; compaction can drop the wake) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 3rd-3 | the "Admit deadline" does not exist; a hook dead between `Resolve` and `admitting` leaves an accepted attempt nothing releases | CONFIRMED (`ledger.rs:627-634` refuses while an attempt exists; `:732-735` `Accepted` retains it; `node_tasks.rs:306-345` has no expiry) | TJ-2: `admitting` written before the `Resolve`; TJ-8 "The accepted attempt with no journal": the extension's `--omp-release-notice`; K0; act 9b, Mutant M |
| ADR-050 3rd-4 | retirement stops at 78; registration stays refused; no surviving retry owner | CONFIRMED on revision 3's text (`finishPending` stopped at 78; `register()` `:505-530` returns on `permanent`) | TJ-6: the ladder continues on 78 with `retired: false`, independent of `confirmed`/`refusal`, restarted by every watcher `ready`; the structured line carries `retired`; act 10, Mutant N |
| ADR-050 3rd-5 | Q7's premises were false as general statements (streaming exec on Cursor; "sent once"; partial-text retention) | CONFIRMED (`cursor.ts:3118-3134`, `packages/coding-agent/src/cursor.ts:609-633`; one `onPayload` is one build; rebuilt contexts omit errored partial text) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 3rd-6 | `Received` suppresses for the old Session only; a fresh conversation shows the same news again | CONFIRMED (`ledger.rs:859-867` marks the old recipient's records; a new session selects by its own cursor; acts 5/6 already expected it) | TJ-8 person-facing sentence corrected and extended (`including what this one may already have acted on`); "What the person sees" states same-Session suppression and fresh-conversation delivery |
| ADR-050 4th-1 | zero callbacks do not prove non-exposure (pi-native, GitLab Workflow send without `onPayload`) | CONFIRMED (`ai/src/stream.ts:1370-1399` short-circuits dispatch for `transport === "pi-native"`; `pi-native-client.ts:45-56` strips `onPayload`, `:179-216` POSTs the conversation) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 4th-2 | acceptance at the next context event is memory-first; a later failure plus OMP's death loses it while Vox's cursor suppresses the news | CONFIRMED (`session-manager.ts:1954-1988, 2158-2178`; `agent-loop.ts:1988-2025, 2091-2100` credentials after context preparation; `ensureOnDisk` `:2788-2793` rejects on the latched failure and is on `ReadonlySessionManager`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 4th-3 | speculative task launch runs a child before the call finishes; the terminal error omits the call | CONFIRMED (`task/speculative-launch.ts:225-242, 291-346`; `agent-loop.ts:2712-2740` `retainCompletedToolCalls`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 4th-P2 | act 10 restarted OMP with the daemon stopped, so registration precedes the check and no `78/retired:false` is established | CONFIRMED (`omp-extension.ts:505-530`) | act 10 restaged with the extension alive (8c's step, daemon stopped before the step ends): the `--uncertain` call itself gets 78 with `retired: false`; Mutant N meets it |
| ADR-050 4th, E-30 | owed; run `e` APPARATUS by its own verdict line | CONFIRMED | run `f` (corrected rig) is the PRODUCT red by its own verdict line; "Experiments" |
| ADR-050 5th-1 | `message_update` is queued asynchronously while `message_end` is dispatched independently; hosted tools leave no signal | CONFIRMED (`agent-session.ts:3943-3999` queue + `queueMicrotask` drain, `:4768-4769` direct emit; `anthropic.ts:651-688` Umans `web_search`, `:2968-3013`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 5th-2 | compaction or notes-backed rollover drops the accepted news after the commit | CONFIRMED (`session-maintenance.ts:1806-1810, 1957-1972`; `session-context.ts:559-625`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 5th-3 | a timed-out `context` handler's awaited qualification can commit after OMP moved on | CONFIRMED (`runner.ts:148-149` 30 s, `:310-395, 1863-1938, 2363-2410`) | **Superseded (row 79, revision 8)**: the class this answered is withdrawn; the current outcome is TJ-3 (iii), uncertain, with TJ-3 (ii)'s non-injection evidence the only cancellation; surviving proof: act 8 (8a–8e). |
| ADR-050 5th-P2 (N) | the watcher-`ready` restart of `finishPending` masks Mutant N | CONFIRMED (TJ-8's second route) | act 10: Mutant N mutates both routes |
| ADR-050 5th-P2 (I5) | I5's zero-count assertion does not discriminate | CONFIRMED | moot in r8: I5 and act 8a‴ belonged to the withdrawn class; the oracle counts a delivery only at the first completed carrying step per identity |
| ADR-050 6th-P1 | `payload.tools` empty proves nothing: tools ride inside the prompt under an owned dialect | CONFIRMED (`agent-loop.ts:2031-2037, 2228-2239`; `task/speculative-launch.ts:244-260, 315-347`) | falls away with the class: the "delivered after an error" class is withdrawn (row 79); the fact is kept in TJ-3 (iii) as the reason |
| ADR-050 6th-P2 (oracle) | accepted history counted as deliveries | CONFIRMED | TJ-10's oracle: first successful carrying step per staged delivery identity; later appearances are history; a second insertion as news is rejected |
| ADR-050 6th-P2 (act 11) | `notice_pending: true` is not evidence | CONFIRMED (`ledger.rs:330-332`) | act 11 stages a distinct `m2` after recovery and asserts the adapter's delivery and the consuming hook's envelope; Mutant O on the missing delivery |
| ADR-050 6th-P2 (act 12 etc.) | act 12's mutant and shipped verdict; knob variants vs controls; act 7's pause file; act 6/G's stdin | CONFIRMED | act 12 asserts the missing 75, CANNOT MEASURE on v0.4.30; B2/E2/8b′ CANNOT MEASURE with named knob-free controls; act 7 removes its pause file on the observed cancel; G no longer drives stdin |
| ADR-050 6th B1–B5 | what ships; early effectful work; likelihood; the middle option; false beneficiaries | CONFIRMED | TJ-8's sentence and "What the person sees" (B1); TJ-3 (iii) and the Context trace (B2); no frequency claimed (B3); "Not chosen in v0.4.31" (B4); the plan/chat/tool-less claims and "widening requires an OMP-core change" removed (B5) |
| ADR-050 7th-P1 | OMP's step replay is decided after the error `message_end` reached the extension | CONFIRMED (`agent-session.ts:4768-4769`, `:3967-4003, 5943-5963`; retry at `:4975-4990, 5223-5231`; the only invisible retry is inside the provider client, `empty-completion-retry.ts:91`) | TJ-3 (i) exemption narrowed to the provider-client boundary; Context, TJ-8 (events and the person's sentence), K20, RS-7 duty 3, act 8f (replay → sentence) and 8f′ (invisible retry → nothing), Mutant Q |
| ADR-050 7th-P2 (act 11) | `m1` asserted on the wrong hook | CONFIRMED | act 11: `m1` once in the recovery hook; adapter delivery; `m2` once in its consuming hook; no repeated `m1` |
| ADR-050 7th-P2 (I2) | the post-commit second-insertion rule cannot catch I2 | CONFIRMED | I2 asserted on the missing TJ-8 sentence and a forbidden later insertion |
| ADR-050 7th-P2 (act 7) | a mutant-only 60 s delay manufactures the red | CONFIRMED | the pause file is removed on the same observed cancel in both runs; a missing cancel is APPARATUS |
| ADR-050 7th-P2 (verdicts) | act 5's blanket "green" is false for its OMP-alive variant; controls unnamed | CONFIRMED (`omp-extension.ts:266-271`) | the verdict paragraph splits act 5 and names every knob-free control |
| ADR-050 7th-P2 (cells) | "Answered by" cells still prescribed withdrawn rules; K4a cited `P_b` | CONFIRMED | nine cells marked superseded (row 79) with the current outcome; K4a cites TJ-3 (ii) |
| ADR-050 8th-P1 | `withReplaySafeStreamRetry` repeats `onPayload`, so the shipped extension already rejects a second build; 8f′ was wrong and Q described an existing safeguard | CONFIRMED (`empty-completion-retry.ts:111-180` calls the attempt factory again; `openai-completions.ts:960` `onPayload` per attempt; `sdk.ts:4721-4722` forwards it; `omp-extension.ts:1241-1253, 1267-1268` count builds; the HTTP retry below the callback is `openai-completions.ts:983-1000`) | three boundaries stated in Context, TJ-3 (i), TJ-8, K20 and RS-7 duty 3; the one-build rule never relaxed; 8f′ asserts uncertain for two builds; 8f″ stages the genuine below-callback retry; Mutant Q inverted; shipped verdicts corrected; the blanket "changes nothing" removed |
| ADR-050 8th-P2 | B2's knob-free control is not green on v0.4.30 | CONFIRMED (the shipped extension never receives TJ-7's sentence) | B2's staging without the halt is PRODUCT red on v0.4.30, as act 3 is; removed from the green-controls list |
| ADR-050 9th-P2 | 8f′'s two carrying builds end with a clean `stop`, so the oracle counts one delivery on the correct product; Q indistinguishable by counting | CONFIRMED | 8f′ asserts the sentence, no accepted record/commit call, no later Vox injection in the old conversation; no delivery count; the fresh conversation's warned delivery kept apart from the oracle; Q red on the sentence and the accepted record/commit; 8f″ says the shim's fetch stub is to be written (OMP 18.20.0 seam: `onPayload` `:952`, `fetchWithRetry` `:983-1000`) |
| task cut, defects 1–24 | acts 6 and 7 lost; the measured trigger not removed; E-30 still owed; `agent_end` resolution; stale step numbers; 78 poison both deleted and kept; two sentences; the Drive turn; act 9b; kills with no means; I2/I5; "delivered twice"; act 10; TR-13; `changed-proofs.md`; verdict per act; TJ-9 proof; lock contention; `/tmp` paths; amendment citations; act 7's staging; knob values; act 1's foreign daemon; latch placement | CONFIRMED, each (the revision note has the per-defect table) | acts 6, 7 restored (Mutants G, H); TJ-4 deletes `news_publication`; "Evidence status" (run `f`); TJ-3 (`agent_end` ends nothing); step references renumbered; TJ-3 Deleted (78 poisons only at `:252`, `:518`); TJ-8 one sentence replacing `:86`/`:80`; TJ-2 Drive path; act 9b one knob; 8b′ and B2 halt steps; I2/I5 reworked; J/J2 on the absent line; act 10 attention-triggered with its premise and foreign-daemon rule; TR-13 gone (r6); `changed-proofs.md` dropped; verdict per act; act 11 (TJ-9), act 12 (lock); paths; citations (r6); act 7's knob; the knob list; act 1's APPARATUS note; the latch deleted |
| new (revision 1) | dangling tickets after a pre-envelope death block the session's attention | CONFIRMED (`ledger.rs:627-634`, `:768-777`, `:1130-1131`) | TJ-2, TJ-8 `prepared`, TJ-9; K3 |

Findings of the ADR-040 reviews outside this lane (trust fence, NW-15, registry, registration,
purge) are ADR-048's, ADR-049's and ADR-040 r3's.

## Experiments

- **E-30, the release-asset red for act 1 (measured by run `f`).** Rig:
  `/opt/vox-evidence/v0431/adr050/rig30.py <run>` (the v0.4.30 release asset copied into the
  scratch root; scratch computer A: `omp-work` kept
  with a passphrase, `robert-work` passphraseless; from run `d` a scratch computer B (`beast`)
  paired with A so the computer is managed and `omp-work` reads `robert-work`'s posts, as
  RcaTrust's `trust.py` does; one room; the real `omp-extension.ts` under RcaTrust's
  `shim-hold.mjs` with `vox-logged`; explicit `--data-dir`/`--config-dir` on the daemon and
  scratch `VOX_DATA_DIR`/`VOX_CONFIG_DIR` on every other `vox`; the forbidden variables
  cleared; no `pkill`: cleanup signals only pids whose command line carries the run root or
  that hold a control socket under it). Act: post `news-held` and wait until `vox room read`
  on `omp-work` shows it; `turn hold r0` (envelope injected, model "thinking"); `vox daemon
  --restart` in a thread; release the commit the moment `node list` stops answering (old daemon
  gone); after the daemon is back, post `news-after` and run three probe turns. Expected on
  v0.4.30: the held turn's `--omp-prepare` exits 1, the notify log shows `Vox: delivery in this
  conversation is uncertain…`, every later `--omp-check-uncertainty` answers 78 and no probe
  turn injects `news-after`. Verdict rule: PRODUCT red if the held turn's envelope carried
  `news-held`, its rc list contains `1`, the notify log has the `uncertain` line and a later
  probe's check is `rc=78`; APPARATUS if the held turn carried no news or the commit was
  released after the new daemon was already Ready.
  - Run `a` (06:55Z): contaminated (the lock was mis-taken) and failed on a flag error before
    any daemon started; discarded.
  - Run `b` (09:18Z, lock held by its own `mkdir`): **APPARATUS.** The two nodes were not on a
    managed computer, so `omp-work` never read `robert-work`'s posts; the held turn carried only
    the membership notice; the extension cancelled it at once (`--omp-prepare` rc=0 in 0.03 s
    before the hold began) and the commit path never ran. Also seen: the commit was released at
    +0.78 s while the old daemon still answered `the daemon is stopping`; the extension printed
    item 40's `node omp-work is unavailable…` line on the watcher's first `unavailable` frame
    and re-registered at +1 s. Receipts lost in the reboot of 2026-11-13; the verdict lines are quoted in `adr-050-revision.md`.
  - Run `c` (09:46Z): **APPARATUS**, same cause after `vox computer personal robert-work`
    alone (the computer stays `individual`; no mutual read). Receipts: `run30-c/`.
  - Run `d` (10:03Z, paired): **APPARATUS**, with a lesson for the staging. With a managed
    computer the news reached `omp-work` in 0.5 s, but each post was delivered by the daemon's
    own attention wake (an **aside** turn, `sendMessage(…, deliverAs: "aside")`, P420-OR-6)
    within a second of the post, before the rig's held prompt turn ran; the prompt turn then
    had nothing to show and was cancelled at once. The receipts also show, on the release
    binary after the restart, the aside at +4.6 s injecting `Vox: could not open this
    session's Session in its room: attention waits for current computer trust` (ADR-040
    NW-8's text, item 28) and `news-after` not injected within the next 6 s. Receipts:
    `run30-d/`. Fix: the apparatus shim (a copy of `shim-hold.mjs` under
    `/opt/vox-evidence/v0431/adr050/`) holds an **aside** turn that injected content while an arm file
    exists; the rig arms it, posts `news-held`, waits for `hold-begin`, then restarts.
  - Runs `a`–`d` (under `/tmp`) were lost with the 07:23 reboot of this Mac; what survives is
    what `adr-050-revision.md` quotes from them (all APPARATUS). The rig was rebuilt
    under `/opt/vox-evidence/v0431/adr050/` (`rig30.py`, `shim-hold.mjs` holding the **aside**
    turn the daemon's wake starts, `vox-logged`, `run-once.sh` gated by `hostguard.sh`), with
    the release asset from GitHub.
  - Run `e` (2026-11-13 09:55 PST, own `mkdir`, `hostguard.sh` OK; receipts
    `/opt/vox-evidence/v0431/adr050/e/`): **APPARATUS** by the rig's own verdict,
    `summary.out:57`: `VERDICT: APPARATUS | held carried news: False | rcs: [] | uncertain
    line: False`. The rig's summary is the verdict; a raw log is not re-read into a different
    one. Two measurement defects were found and fixed for run `f`: the summary tested the
    `INJECTED` line truncated at 160 characters for the posted text, and read `calls.log` for
    the prepare's exit code before the hook's `END` line had landed.
  - Run `f` (2026-11-13 19:25Z, own `mkdir`, `hostguard.sh` OK, corrected rig; receipts
    `/opt/vox-evidence/v0431/adr050/f/`): **PRODUCT red** by its own verdict line
    (`timeline.log:61`), quoted with the sequence in "Evidence status". The rig's verdict
    requires all four: the held envelope carried the posted news, a prepare exit code 1, the
    `uncertain` line, and `news-after` not shown; all four hold.
- Retained receipts read, not rerun: RcaTrust `run-s3` (instrumented red), `run-c1.out:47-48,
  66-67` (release, rc=0: commit released after Ready), `run-c1/shim.log:5-7`
  (`vox-context-staged` then `vox-context-accepted` within 1 ms: the extension's own record).

## The decider's recorded answers, as applied

- **Row 36 (Q3).** A possibly shown turn with no durable decision: uncertain for good; nothing
  shown again. Applied in TJ-3 (iii) and TJ-8.
- **Row 67 (Q7).** "Treat it as delivered", on the premise that the agent ran nothing. Applied
  nowhere in v0.4.31: Vox's extension cannot establish that premise for any request that could
  call a tool, and the request's own fields do not show what the model could call (sixth
  review P1). He was told.
- **Row 79 (Q8).** "Keep the safe outcome: after such a failure the conversation stops using
  Vox, says so in one plain sentence, and you start a new conversation to keep using Vox there.
  No risk of a double action." Applied in TJ-3 (iii) and TJ-8's sentence; the checked middle
  setup is recorded under "The decider's answers" as not chosen.
- No question remains open for him in this ADR.
