# ADR-038: Daemons Trust Daemons, and Sessions Are Presence

- **Status**: Proposed, after v0.4.6. The decider's product rulings of 2026-10-19 (one question
  at a time, quoted below) are the accepted product requirements; undecided presentation details
  remain proposed. Execution, acceptance and delivery are recorded on the source-bound GitHub
  issues, separately from decision status. Each requirement MUST land with its proof (ADR-018)
  in a small release (FX-19).
- **Date**: 2026-10-19; amended 2026-10-20 (FX-22–FX-27, the daemon's CPU); amended
  2026-10-20 (FX-28–FX-34: the idle daemon's disk and CPU, measured on v0.4.9, the own-feed
  recovery ruling of 2026-10-19, a retention change that poisoned a room, and a node on Linux
  that could not be unlocked); amended 2026-10-21 (FX-35: a daemon whose parked flows held
  the flow-state pool synced nothing); amended 2026-10-21 (FX-37: room creation overflowed a
  normal Tokio worker stack while reconstructing an ML-DSA root key for one signature); amended
  2026-10-21 (FX-28: observable needless work, not a machine-dependent CPU cutoff, is the verdict);
  amended 2026-10-23 (FX-28: atomic node application, durable room-admission rollback, fresh
  pairing requests, observation deadlines that do not discard valid work, and the rendezvous
  registration handoff); amended 2026-10-23 (FX-35: the decider approved exact running capacity
  per active-or-retiring hosted identity, with no fixed floor); amended 2026-10-24 (FX-35:
  resource ownership, fair admission selection, Busy attempt credit and legal proof staging)
- **Deciders**: Robert E. Lee
- **Tags**: trust, daemon identity, sessions, presence, agent comms, sync, health, releases
- **Related**: ADR-018, ADR-020, ADR-026, ADR-029, ADR-031, ADR-033, ADR-034, ADR-035, ADR-036,
  ADR-037

## Context

Vox's agent comms exist so the decider can drive his dark factory from a room: he asks, every
relevant Session answers, work is claimed and handed off in the room, and progress and proof land
on GitHub through awa (ADR-020, ADR-021, ADR-033). Every requirement here is judged by whether it
removes friction from that, with awa as the scoreboard; what does not is polish and ranks below.

v0.4.6 shipped on 2026-10-19 and was used the same day on the decider's two Macs, five nodes in
two rooms. His verdict: "at some level we might be up and working again but we have so much
polish that we need to apply", "everything feels like a brittle mess right now especially the
trust relationships between computers". What the daemon and the keyrings showed:

- Every keyring on the work Mac was filled by hand, and they disagree: one agent node does not
  trust the other Mac's personal node at all; one keyring names that personal node after an
  agent; only one agent node trusts the other Mac's OpenCode node; `vox computer status` says
  "individual". The pair-once path of ADR-035 exists (`Add Computer…`, `vox computer invite`,
  `vox computer pair`) and was never put in front of him: `vox room join` ends by telling the
  person to run `vox trust add` per node and to ask the other computer's operator to accept a
  fingerprint; the app raises trust offers one node at a time; `Add Computer…` sits under
  Settings and nothing else names it. "It was filled in by hand because nothing made it
  obvious how to not do it by hand."
- An agent node sat in a room with nothing behind it: "opencode-work is supposedly in the room
  but it can't see/do anything". The daemon listed four open Sessions in that room; the app's
  member panel showed none.
- The app showed "no completed sync in 10 minutes" on both rooms while every room synced about
  once a second per peer, and the daemon idled at 50–67% CPU. Reproduced from scratch with the
  signed binaries (four nodes, one room, one post each, 60 idle seconds): v0.4.6 ran 204–219
  rounds per peer at 40% CPU with "last sync never"; v0.4.5 ran 2–3 rounds per peer at 3% with
  "last sync 21 s ago". The sync lane records none of its completed rounds as a sync; a hint
  that arrives for a head the node already holds starts a round that makes no progress, waits on
  nothing, and is retried at once. Under that load the daemon did not answer a harness hook
  promptly, in two sessions' hooks.
- Replying to an ask with the entry prefix `vox room read` prints was refused ("this node cannot
  read that message"); the full entry hash worked.
- Rooms from before the v0.4.5 format showed "Legacy history required; Resume or Cancel". He
  deleted them and started fresh.

The decider then answered twelve questions, one at a time. His answers are the decision.

## Terms

- **Daemon identity**: the persistent identity of one computer's `vox daemon` (ADR-035 CT-1).
- **Daemon trust**: mutual trust between two daemon identities, one ceremony each way; it covers
  every node either daemon manages, now and later (ADR-035 CT-3).
- **App-bound node**: on a Mac, the node Vox.app is bound to (ADR-035 CT-13's selected personal
  node); on a headless computer there is none.
- **Session**: one harness session's record in a room (ADR-029).
- **Presence**: whether a node in a room is backed by live Sessions, and which.
- **Phantom**: a member that reads as active while no Session backs it.

## Requirements

### 1. Daemons trust daemons

> "I would love it if Computers had identity and that I can set up a trust relationship between
> two computers so I don't have to fuck around at the individual node level -- Sorry I said
> computer but really we're talking about daemon level identity/trust."

- **FX-1.** Daemon trust is the intended way two of the person's computers meet. ADR-035 CT-1
  through CT-22 and its accepted technical contract stand; this ADR requires that path to be the
  obvious one and the per-node path to be the exception reserved for other people's nodes
  (CT-2).
- **FX-2.** Daemon trust MUST be mutual: "You trust daemon A with daemon B once <-- yes and B
  must trust A once too -- kind of like we were doing at the node level, but at the daemon
  level." One ceremony in each direction; nothing per node afterwards.
- **FX-3.** Drive follows the app binding, never a name: "special treatment of the node bound to
  the app (for macos) to ensure that node-1 (bound to app) from daemon-A gets drive access for
  the nodes of daemon-B that are not bound to the app from that other computer -- and vice
  versa"; "it's based on node bound to app -- not name". Agent nodes MUST NOT drive agent nodes
  through daemon trust. A headless computer has no app-bound node (ADR-035 CT-13, `vox computer
  personal --clear`): nothing on it drives the paired computer's nodes, and the paired Mac's
  app-bound node drives the headless computer's nodes.
- **FX-4.** Nodes of a trusted daemon MUST appear under the names their owner gave them, with
  no typing ("yes, should show names owner gave them"); a local rename stays available and is
  the exception (ADR-035 CT-5).
- **FX-5.** A computer without the app MUST join daemon trust by one command in its own
  terminal ("acceptable for me to ssh to the linux machine and run a command to have it trust
  another daemon"); the app MUST NOT be required for it (ADR-035 CT-6).
- **FX-6.** The product MUST lead to daemon trust wherever two of the person's computers first
  meet, and MUST NOT steer to per-node trust there: when a node of this daemon shares a room
  with a node of a daemon this one does not trust, `vox room join`'s output, the app's trust
  offers, `vox trust offers`, `vox setup` and `vox agent status` MUST name daemon pairing first,
  with the exact app step or command, and MUST say that it replaces the per-node grants for
  every node of both computers (CT-4). Per-node `trust add` MUST still be offered for a node
  whose daemon is not the person's.
- **FX-7.** When daemon trust is established between computers that already hold hand-made
  per-node grants, the daemon policy MUST replace those grants (CT-4, CT-16), and the app and
  `vox trust list` MUST show the resulting trust for every node of both computers, named by
  source ("from computer trust", "individual").

### 2. Presence is Sessions

> "trust is at the daemon or node levels .. that makes sense to me -- being able to join a room
> is with the room url and passphrase --- but being in the room, especially for a node doing
> agent work, is really at a session level .. otherwise we have nodes in rooms with no sessions
> backing them .. so they're like phantoms"

- **FX-8.** The model is: trust belongs to daemons and nodes; joining a room is the room's link
  and passphrase; an agent node's presence in a room is its live Sessions. A node with no
  Session in a room is a member and MUST NOT read as active there.
- **FX-9.** A node MUST NOT leave a room because it has no Session: "it's not that a node needs
  to leave a room when there's no session .. but we need to be able to disambiguate node backed
  by session or not." Every surface that lists a room's members (the app's member panel and
  roster, `vox room roster`, `vox room sessions`, the harness hook's room news, `vox room
  ping`) MUST show, per node, whether live Sessions back it and which.
- **FX-10.** One node with several Sessions in one room is the ordinary case ("the same node
  might have n-count sessions"; "codex-beast might have 2+ sessions in the same room"). Each
  Session MUST be shown, addressed and answered as itself.
- **FX-11.** The app MUST show a room's Sessions where it shows the room's members. How the
  member panel and roster present nodes, Sessions and drive is design work the decider called
  for ("this really needs some deep thinking behind it"): a design story under this ADR MUST
  produce that presentation and amend FX-9–FX-11 with it before the stories that build it start.

### 3. The room reaches an idle harness window

- **FX-12.** New room messages MUST appear in an idle harness window as they arrive ("new
  messages should appear in an idle harness window as they arrive"), not only at the top of the
  next turn. Where a harness has a native path, Vox MUST use it (OpenCode: the installed TUI
  plugin). For windows the person opened by hand in Claude Code and Codex, Vox MAY deliver
  through tmux ("I can drive all harnesses via tmux if needed"); `vox setup` and `vox agent
  status` MUST say which path each harness uses, and the hook's per-turn drain remains the
  record of what the model read. This widens ADR-020's announce-only wake from urgent messages
  to every new message.
- **FX-13.** An ask addressed to no one MUST be answered by every Session in the room that
  finds it relevant to its own work, at that Session's next turn; those answers MUST NOT
  provoke answers to one another; an ask that names a Session or node MUST be answered by the
  addressee only. "As a human user in the room I want to be able to ask … and get a status
  update from everyone in the room -- That doesn't mean that everyone should then start cross
  chat pollination with everyone else's status." The agent skill pack MUST say this.
- **FX-14.** `vox room post --re` MUST accept any entry prefix that `vox room read` prints and
  that names one entry, exactly as `--before` does.

### 4. An idle Vox costs nothing and tells the truth

> "I mean sure -- but I'm wary of foot guns -- so maybe if you find something in violation flag
> it to me then."

- **FX-15.** A quiet room MUST run no sync round without a need the status can name; the
  periodic request (ADR-025 D7) remains the only cadence. The proof drives the shipped binary and
  asserts rounds per peer, idle CPU and what `vox status` names, never an internal state. This
  is measured, not gated: no threshold is added to the product; a violation is reported to the
  decider with its measurement (ADR-037 R13). Measured cause on 2026-10-19: the settlement tick
  offered the node's own head to every connected peer every second, and the lane never recorded
  a peer's acknowledgement, so the hinted round that fetched nothing ran again each tick.
  Cross-story evidence on 2026-10-21 is diagnostic, not acceptance: the #986 shipped-binary
  journey at exact candidate `2db45720f9af55adfca230e01b1208289a6b33d0` (based on
  `b6e7b0d93`, without #996) restarted Alice, accepted Bob's post `after alice's daemon
  restarted`, and then never showed that post to Alice while Alice reported Bob's lane at 608
  completed rounds, zero failed or partial rounds, no running round, and eight board records
  received. Fresh commands still answered and completed rounds kept increasing, so this was
  structural non-delivery rather than a stopped process. That candidate still let
  `offer_inventory` credit a peer's scalar echo of the sender's accepted own head even though
  the echo proved neither the owed body nor its semantic effect; that reachable path could then
  suppress the sender's own-head offer while empty rounds continued to complete. #996 removes
  that inventory credit and accepts only an authenticated, role-complete receipt. The source
  comparison therefore makes the #986 restart journey depend on #996 and names a concrete cause
  consistent with the observation; it does not prove that #996 fixes that exact journey. The
  #986 journey MUST run on the composed #996 candidate before either story cites this wedge as
  fixed.
  Decision (the decider, 2026-10-21): `held_through` is the last authenticated feed position the
  peer has completely satisfied for that peer's role. An authenticated header whose private
  payload and effect are addressed only to another member counts as satisfied without the other
  member's payload; it MUST NOT cause a permanent receipt probe, partial round or repeated offer.
- **FX-16.** `vox status` and the app MUST record each round the lane completes as the room's
  and the peer's last completed sync; "no completed sync" MUST fire only when it is true
  (ADR-034 §5 "Health is true", HL-1; PRD-001 R35).
- **FX-17.** The daemon MUST answer its control socket within a harness hook's wait while it
  syncs; a hook that reports "the vox daemon here did not answer promptly" on an idle machine
  is a product defect.

### 5. No legacy

- **FX-18.** Rooms from before the v0.4.5 format are not supported: "we're still building vox
  and have no users -- I want to continue to design freely without overengineering backwards
  compat." The legacy history recovery flow (ADR-036's "Legacy history required", resume and
  cancel) MUST be deleted, with its prompts, states and proofs. The refusal and the deletion
  apply to rooms in the pre-v0.4.5 format only; a current-format room whose requested history
  is unavailable keeps ADR-036's live and requested-history journeys (H-1–H-8) unchanged. An
  unsupported room MUST be refused with one sentence naming what to do (leave it and create a
  new one). Real data MUST NOT be deleted or reset by Vox.

### 6. How this ships

- **FX-19.** Releases MUST be small and incremental until Vox is back to "somewhat usable":
  each cut is one clean batch of fixes from this ADR, published and closed with its release
  milestone (v0.4.7, v0.4.8, …).
- **FX-20.** Two tracks MUST run in parallel: a scripted walkthrough of two computers that the
  decider drives (fresh install, daemon trust both ways, a repo room, Claude Code, Codex and
  OpenCode, one task end to end), with every surprise recorded as a defect under this ADR; and
  the known defects above turned into stories and fixed now. The walkthrough and all staging
  MUST run on the VM setup (the macOS guests of the v0.4.4 app-proof work), not on his working
  Macs ("use the VM stuffs so I'm not losing ability to use my macs").
- **FX-21.** Every product requirement above (FX-1–FX-10, FX-12–FX-18, FX-22–FX-24, FX-26,
  FX-27, FX-28–FX-35, FX-37) lands with a proof that drives the shipped `vox` binary as a person
  would, with a mutant that turns it red on its own assertion (ADR-018). The two-computer requirements
  (FX-2–FX-7) are proved by two daemons in two data roots on one machine. FX-11's design, FX-19,
  FX-20 and FX-25 are process rulings: FX-19's record is each closed release milestone, FX-20's
  is the walkthrough's defect record, FX-11's is the amendment it produces, and FX-25's is each
  release's asset list.
- **FX-22.** A governance question about a room (who may read whom, who has consented, what a
  member offers) MUST answer entirely from the room's in-memory semantic projection, without
  opening the store or decrypting even the governance index header, while that semantic meaning
  is unchanged. Decision: the room keeps its folded consent facts in memory (per author, the
  readers it consented to and its reset sequence), never a store snapshot, page or row vector, so
  the index's bounded-turn rule stands. Acceptance of a fact whose canonical authorized meaning
  changes the projection, and expiry of authority at its exact recorded deadline, causally
  invalidate and rebuild that projection; sequence-only, unauthorized, superseded and same-value
  facts do not. The internal durable revision tracks canonical work, while the published display
  revision moves only when a completed fold changes what a person sees. The sealed index remains
  the only durable representation, and a restart rebuilds in bounded turns from the index and the
  entries it names, never by replaying the log. Measured
  cause, 2026-10-20 (the decider's daemon, vox 0.4.7; `ps` 155–170% of a core; two 10 s `sample`
  runs, 13,558 busy samples each, about 1.36 cores): 72% of all busy CPU was the status
  publication and 44% of all busy CPU was `trusted_by`, which opened a fresh view (a store
  snapshot and a decrypt of the index header) and asked `can_read` for every ordered pair of
  members; each answer walked the sealed index (a decrypt per page), decrypted the log entry it
  named, walked the index again for that entry's binding, and looked up the consent reset the
  same way. 48% of all busy CPU was decrypting store segments to re-read facts the daemon had
  already folded; nothing was cached ("no snapshot, row vector, or page survives a caller's
  bounded turn"). A publication that reuses an unchanged room's detail (#990) still opens the
  store for each room's revision check and re-pays the whole walk on any governance change.
- **FX-23.** Every AES-GCM operation in the shipped daemon MUST use the processor's AES and
  carry-less multiplication when the processor has them, with the software implementation in
  the same binary as the fallback otherwise. Decision: aes-gcm 0.11 (aes 0.9, polyval 0.7),
  which selects the backend at run time. Measured cause, the same samples: the `aes` 0.8.4 and
  `polyval` 0.6.2 crates under aes-gcm 0.10.3 compile their ARMv8 backends only under
  `--cfg aes_armv8` and `--cfg polyval_armv8`, which no build set, so every decrypt on Apple
  silicon ran the bitsliced software AES and the software POLYVAL (`aes::soft::fixslice`,
  `polyval::backend::soft` were the hottest leaves); Keccak autodetects and was not affected.
- **FX-24.** A preparation turn in which the step did no work MUST end as a wait, never as
  progress, on the thing the step waits for, in the words `vox room list` and the app show.
  Measured cause,
  2026-10-20: the decider's room ended every preparation turn on "refreshing its Session
  records", reported as progress, because the refresh stopped at its first gate; the room was
  re-queued after the 50 ms fast retry, about five turns a second as measured, and each turn
  ended in a publication that paid FX-22 through FX-23; `ps` showed 174% of a core on the first
  #991 build, and the app had said "Preparing room history" for twenty hours.
- **FX-25.** Every release MUST publish the unstripped daemon binary beside the stripped one it
  ships, so a profile of the shipped daemon symbolizes without a matching local build. Cause:
  the 2026-10-20 samples of the v0.4.7 helper had to be named by matching its machine code
  against a local build of the same version.
- **FX-26.** A room's private Sessions (restore, controls import, legacy steps, pending
  activity) MUST be advanced during the room's preparation, one bounded step per turn, so a
  restored room's Session-record refresh can finish before the room is published. Cause: these
  advanced only for a published room, and the refresh waited on them, so a room restored with
  such state never opened (the decider's room, 2026-10-20).
- **FX-27.** The daemon MUST NOT delay, skip or space any turn, publication or sync round by a
  rule that counts turns or measures CPU time. FX-15's retry of a repeated wait is not such a
  rule and stands unchanged. Ruling: "caps on cpu seem like … footguns", "we need to understand
  what is driving the cpu inefficiency rather than capping the cpu" (the decider, 2026-10-20,
  rejecting a ten-fast-turns-then-one-a-second cap proposed for FX-24's cause).
- **FX-28.** A change to the person's computer trust (ADR-035: a policy revision, a node
  attaching or detaching, a computer joining or leaving the roster) made on either of two paired
  daemons MUST show on every attached node of both: `vox computer status` asked of each such
  node names the new policy (the computer added or removed, the drive granted or revoked, the
  node attached or detached in the bound roster) within 5 s of the change on the daemon where
  it was made, whatever the other daemon does; on the other daemon within 5 s of the exchange
  the changing daemon starts for it (#989) completing, and, when that exchange does not
  complete (the peer unreachable, the stream cut), within 60 s, the fallback exchange's
  period, after the peer becomes reachable again. Two daemons on which nothing changed MUST
  start no pairing exchange except FX-15's named fallback and MUST derive no node binding again.
  A node actor which has not applied the revision at the local observation boundary remains
  attached but non-authoritative: status names it pending and its prior projection fails every
  current-policy fence. The accepted application retains ownership and continues when its queue,
  room lock or storage can progress. Crossing the observation boundary records lateness; it is
  not an authorization lease and MUST NOT discard still-current work or its unlocked credential.
  Only an actual policy/expiry change, detach, lock or shutdown supersedes that work. Completion
  clears the exact owned pending result while preserving the historical miss. A later unrelated
  policy action, restart or manual retry MUST NOT be required to recover. Startup follows the
  same distinction: it derives and applies the actual current binding before Ready, repeating
  only for actual policy supersession within the same accepted startup operation. The shipped
  journey holds an accepted actor past its observation boundary, observes the miss and fail-closed
  state, then releases that event and requires usable current authority without another policy
  action. A late completion never rewrites the original miss as on-time.
  These are the shipped, user-visible work records; a machine-dependent CPU threshold is not a
  verdict. "We need the detection of change logic to be sound. Easy for local daemon to notice,
  but daemon to daemon update needs to be solid" (the decider, 2026-10-20). Decision: a node's binding is derived
  once per revision of the computer policy and on no timer; a change made on the other daemon
  arrives in the pairing exchange that daemon starts, and a merged exchange that moves this
  daemon's revision is a change here, so detection on either side is the exchange itself.
  Measured cause, 2026-10-20 (the decider's daemon, vox 0.4.9, four nodes Ready in eleven
  rooms, no room gaining an entry; `ps` 0.63 of a core at steady state; two 10 s `sample` runs
  symbolized from the release symbols, FX-25): 21–24% of the busy CPU was
  `prepare_computer_binding` → `Computer::bind_node` (`State::derive` and `Binding::verify`: an
  ML-DSA verification of every management event, `CompositePublicKey::from_bytes` expanding the
  key for each), reached from a 1 s `tokio::time::interval` in the host's `follow_computer_trust`
  that calls `reconcile_computer()` for every attached node every second and then
  `record_application()`, which derives again; a further 6–8% was the app's polling re-deriving
  the same state per control answer (`individual_trust_eligibility` → `Computer::capability` →
  `Binding::verify`). Four nodes, nothing changed.
  Deadline contract and RCA, 2026-10-21: an early FX-28 repair converted its local monotonic
  deadline to Unix milliseconds and the answering daemon subtracted its own Unix clock. Those
  clocks need not agree: a receiver ahead could expire valid work immediately, while one behind
  could extend it. A causal deadline is therefore never transported as an absolute time. The
  initiating daemon owns and enforces its original monotonic `Instant` through dial, exchange and
  local reconciliation. Its hello carries only the duration budget remaining when the hello is
  sent. Immediately when the complete authenticated hello is received—before echoing it or reading
  its payload—the answerer caps that duration to the operation's public contract and applies it to
  its own monotonic clock. The complete length-prefixed frame (length and body together) uses that
  one absolute end; neither half renews the remainder. A state transaction checks it before
  executing, then stages and flushes its replacement file, checks again at the atomic rename
  boundary, and publishes the in-memory state only after that commit. There is no second outer timeout: it would truncate the ten-minute
  pairing contract or mint a fresh ordinary-exchange clock. This bounds remote transaction and
  reconciliation work without claiming to reconstruct the initiator's instant. Network transit
  continues to consume the initiator's original deadline. If repair begins only after that
  retained deadline, the initiator durably records the miss before attempting repair. That record
  is historical truth about the original cause, not authority over the receiving daemon: the
  complete authenticated exchange being merged is itself the repair and the receiver applies its
  signed policy under the causal boundary of that exchange. On return the initiator records
  `repaired-late`; restart and a same-state failed preview preserve both the miss and repair. No
  second exchange is required merely to tell the receiver that the first restored exchange was
  successful. A later operator policy change replaces the old cause in current convergence status,
  but neither it nor a repair rewrites the original miss as on-time. Decision, 2026-10-23 (the
  decider): a new explicit pairing request owns its admission boundary; it MUST NOT inherit an
  older background exchange's elapsed deadline. The old cause keeps its miss and unfinished
  obligations while the new request checks the code under the existing verification and approval
  rules. A preview does not acknowledge background delivery. Reserving the peer for that request
  does not suppress observation of an older background miss or manufacture another sync attempt.
  Rendezvous RCA, 2026-10-23: the invitation was saved and returned before its background
  `ComputerRegister` reached the anchor. Redeeming that otherwise-valid code could therefore
  report a store-policy refusal before any code verification. Missing publication is an
  availability handoff: the one authenticated redemption waits for that exact owner/registration
  to appear, with its event registered before the absence check. Registry transitions and their
  notifications share one serialized order. Actual owner, token, expiry and serving-policy
  refusals remain terminal; a direct connection independently races this path. The waiting
  service task retains no history-flow charge or management permit needed by registration, and
  cancellation of the caller's stream retires its scoped waiter. Known revocation of an existing
  registration is retained through that registration's recorded expiry; no expiry is invented
  for an unknown record or after an anchor restart. Active and unexpired revoked records share
  the anchor's existing global, owner and source retention budgets, so recent withdrawals can
  produce an ordinary capacity refusal without evicting live evidence. Transport connection,
  registration, redemption and response reading spend the caller's one original boundary;
  private 15 s and 30 s wrappers cannot truncate a valid pairing wait. The shipped anchor journey
  holds the exact inviter registration, observes the redeem request reach that missing record,
  releases publication and requires the same command to authenticate the code. Reintroducing
  the former immediate policy rejection makes that user command fail on its own assertion.
  Local application ownership is separate from the transport exchange's bounded attempt. The
  daemon-to-node event names the exact policy revision and expiry plus its attachment/pass owner.
  Its retained observation deadline classifies on-time versus late; true supersession cancels
  obsolete work. Every durable actor stage and the final writer fence validate that exact current
  policy. The owner keeps awaiting the same accepted event after reporting lateness, with no fresh
  clock, timer-driven reconciliation or retry-count cap. The shipped journey causally holds one
  actor, proves its healthy sibling applies while the held actor stays Ready without claiming
  the new grant, and then releases that exact message. Its automatic completion clears pending
  while the latest local miss per node remains durably visible across restart. The shipped journey
  also restarts one daemon with its Unix clock one hour ahead and then proves changes in both
  directions from a causal observation on the proof process's monotonic clock, never by comparing
  either daemon's Unix timestamp. After those clock-independence and quiet-boundary claims, its
  first fresh-room join also proves the skewed publisher stops at the board's named `Clock`
  refusal rather than proceeding without a pre-join record and blaming authentication. The daemon
  is then restarted without the test-only clock step before the independent stale-rekey claim;
  rendezvous's five-minute future-date security bound is deliberately not a Computer deadline.
  A recovery proof evaluates no PRODUCT
  timing verdict until it has causal apparatus evidence of reachability (the restored anchor's
  latest event-driven view names both exact management fingerprints, or a round trip has completed
  through the exact userspace forward); failure to establish or retain that precondition is
  APPARATUS/NO RESULT, never a PRODUCT retry verdict. The retained local deadline still measures
  the real restoration event. Absence of idle derivation is compared across the next dated,
  completed fallback exchange named by the same shipped status snapshot as the binding evidence,
  not an arbitrary quiet window: the unchanged revision is a structural cause boundary and every
  binding's durable derivation record must remain identical across it. A complete ordinary
  exchange is bidirectional: the starter sends its snapshot and the answer returns the peer's
  snapshot, so that one completion paces both daemons' fallback clocks. The quiet proof therefore
  requires one such pair exchange, not one independently originated exchange per daemon. It admits
  a second attempt only when both named fallback instants were already overlapping. Every recorded
  completion must advance the opposite daemon's `last_answered_exchange`; an overlapped attempt
  without its own completion is covered only when that same daemon answered the successful peer
  round and retained no failure. CLI JSON, plain CLI, the app
  FFI and the native Computer Trust screen expose the exact missed revision, whether it repaired
  late, and whether it is expired, replaced, pending or converged, alongside policy revision,
  per-peer exchange records/counters and per-node binding revision/derivation moment. Neither
  client has to infer currentness from elapsed time or free-text failure wording.
  Each per-peer application also names `exchange_in_flight`, true for the whole reservation from
  selection through completion. Attempts say that work started and exchanges that it completed;
  this bit closes the otherwise invisible interval between them, so a person can distinguish a
  tail still applying receipts from an idle daemon or a wedged attempt. The quiet-boundary proof
  takes this bit, both counters and binding/currentness from one shipped-status snapshot per
  daemon. It begins the unchanged-state claim only at `false`; failure to become false while the
  same policy remains current and confirmed is PRODUCT (either another pre-fallback attempt or one
  attempt exceeding its existing return contract), not an apparatus sleep and not a renewed
  timeout.
  Crash and late-marker amendment, 2026-10-21: the transaction which commits an effective
  operator-policy change also durably records every exact peer and that policy revision as
  unresolved; this ordering leaves no crash window between publishing the cause and owning its
  consequence. A later exchange may carry transport/journal records too, but it retains that
  operator-policy cause rather than replacing it with the later journal number. Only the
  complete exchange returning within its boundary durably clears that obligation; a crash after
  merge but before that acknowledgement therefore fails closed rather than inventing success.
  Deadline expiry promotes it to missed before any late repair proceeds; after a process crash, an
  unresolved obligation is likewise recovered as missed, because restart has no evidence that
  it completed within the lost monotonic interval and MUST NOT create a replacement clock. A
  newer operator revision owns its own already-created causal deadline; an older unresolved or
  missed revision is historical `replaced` evidence and cannot shorten that new clock.

  Revision numbers remain local and are never translated by ordinal position. The durable state
  separately names the journal revision of its last effective operator-policy change: endpoint
  and reachability records may advance the journal but cannot replace an operator-policy cause. A wire miss marker
  therefore carries a digest of the exact canonical policy frontier (genesis, pending enrollment
  and signed policy history; not reachability records, receipts, convergence observations or local revision numbers). The
  receiver correlates it with that frontier only after merge. A marker for an older frontier cannot
  affect unrelated newer local policy, and a matching marker cannot revoke the policy carried by
  the authenticated exchange that delivered it. The earlier design did exactly that: the receiver
  merged the policy, classified it expired from the sender's pre-repair marker, and removed every
  managed grant; the sender marked the exchange repaired only after sending and then correctly
  suppressed unchanged work, so the receiver could never learn the bit that would unexpire it.
  Missed and repaired-late remain durable, user-visible convergence evidence on the initiating
  daemon. A successful repair clears current consecutive failures and their backoff, and resumes
  the ordinary named fallback; historical lateness must not disable future liveness work. The
  authenticated traffic of that same repair can also finish its retained reachability waiter while
  the exchange is in flight. Success consumes that queued wake only when the sent snapshot covers
  both its journal and operator-policy revisions. This prevents the repair from scheduling a
  redundant full exchange while preserving a policy or journal cause committed during the flight;
  wall-clock quietness is neither the state machine nor the evidence of coverage. Every retained
  failure deadline names the operator-policy revision which owns it. A reachability mark from an
  older policy is a barrier until the already-queued newer `ComputerChange` installs that newer
  policy's original deadline; it can neither expire the new policy nor be discarded in favor of a
  fresh clock. Reachability snapshots and inserts its mark while holding the policy state, so an
  old mark cannot be inserted after the newer event has already been consumed; without that one
  boundary the old barrier could suppress every later fallback. A complete inbound ordinary exchange is bidirectional repair: its reply carries this
  daemon's current snapshot, so it clears operational failure and paces the fallback. Outcome
  recording serializes that reply with an overlapping outbound flight; when the reply covers both
  of a causal retry flight's revisions, that flight is superseded and cannot recreate a durable
  miss after the reply cleared the same obligation. An ordinary quiet fallback has no such
  obligation: simultaneous fallbacks may both finish once, rather than one canceling the other and
  manufacturing a second local attempt. The inbound success covers the exact noncausal flight:
  its later success may still be counted, but its later error cannot overwrite that success. Only
  a causal flight's expired deadline can create a durable policy miss; a quiet fallback's transport
  bound is operational, never authority over the current policy. Receiver
  authorization instead fails closed while its durable node application is behind
  the merged policy revision, and becomes current only after that exact projection is saved and
  receipted. An older policy revision's reconciliation result cannot detach or displace that
  recovery.

  The answerer's hello echo and every response frame share the same local absolute deadline as
  its read and transaction, including both the frame length and body; a peer which stops reading
  cannot retain one of the bounded answer slots past that deadline. Actor publication checks the
  same deadline and cancellation after the durable application receipt and after every live
  publication stage; a late boundary empties registered reacher gates. Startup reconciliation
  uses one causal Unlock boundary and continues on actual revision movement, with no eight-pass
  verdict and no per-pass renewed deadline. The optional shipped-binary journey parks an answer
  after its merge, proves the answerer's effective keyring contains the newly applied grant,
  observes the initiator's structural missed-revision state, then restores the exact authenticated
  path and proves the carried policy is applied to every receiving node while the initiator still
  names the original miss as repaired late. Its mutant suppresses the repair application, so the
  effective-keyring assertion—not elapsed sampling—turns PRODUCT red.

  Application handoff, 2026-10-23: preparing an application MUST durably retain the exact
  rollback obligation before changing the node store. The keyring, pending removal locks,
  pending consent keys and consent ordering MUST commit together in one node-store batch.
  The Computer writer fence validates the same policy revision and expiry state before that
  batch; policy changes cannot interleave with its commit. The short state lock MUST NOT span
  node-store I/O. Live trust marks likewise install only after their durable batch commits.
  Once an application receipt is current, the actor MUST publish its committed revision and
  trust view before an elapsed-time verdict can return; recording a missed boundary cannot
  strand a completed application behind an older live projection.
  Every reconciliation pass owns a distinct identity even at the same policy revision; a
  superseded pass cannot clear or overwrite its successor's pending result. Endpoint observations
  update reachability without renewing an application deadline. Node attachment uses the
  policy cause's retained deadline; a later effective policy change owns its own new cause.
  Clients show current application confirmation, historical lateness and current reachability
  separately: neither late repair nor an unreachable peer erases a confirmed application.

  A refused or interrupted room join MUST retain cleanup before publishing any prejoin, member
  or bundle record remotely. Before the responder admits a member, it proposes the exact
  admission fields under a signature domain distinct from the final join witness. The initiator
  verifies that proposal and durably covers its epoch and timestamp in its withdrawal journal
  before acknowledging its hash. Only then may the responder admit and return the final witness;
  the initiator verifies its signature and equality with the prepared fields. A proposal alone
  grants no admission authority, and validation-only exchanges admit nobody. Final admission
  rechecks the exact room instance, attachment, epoch and responder's current membership under
  the room lock. The author and its admission notice MUST commit in one store batch before
  success; neither live projection advances if persistence fails. Member withdrawals
  can authenticate against the exact held prejoin root key, remove covered prejoins as well as
  member/bundle records, and prevent replay without blocking a genuinely later prejoin. The
  board rejects future-dated withdrawals before storing either pending or applied state. A
  current-policy fence closes the successful join's cleanup obligation; failure or restart keeps
  it until withdrawal is complete. Sender-key authority proofs stage the exact protected entry
  at the recipient before releasing a held key batch: lack of ciphertext or receiver-side policy
  revocation cannot substitute for proving the sender's final admission fence.
- **FX-29.** A sync round that brings this node nothing (no entry, header, proof or key it did
  not already hold) MUST write nothing: over a quiet minute a member's store MUST gain no
  commit at all from its rounds. Decision: a hint this node holds (its committed head, its
  control readiness and its live window all at the hint) is not pulled again each period; a
  hint whose missing pages a peer said it does not hold is not pulled from that peer again
  until that peer's inventory changes; a head or header already held is not saved again; and a
  verifier persists its progress once per proof verified to its end (an inclusion proof or a
  control range), never once per Merkle join, since a proof is bounded and is verified again
  from its bytes after a crash. Measured cause, the same daemon: 1,367 durable store commits per second across the four node stores
  (redb transaction ids read 30 s apart: robert-work 524/s, opencode-work 495/s, codex-work
  197/s, claude-work 151/s; robert-work's store at transaction 20.4 million) with no room
  gaining an entry. By site, ≈64% of commit wall time was `history_stream::admission::advance`
  committing the context and the cursor after every `Progress` step of `ControlRangeVerifier`
  and `InclusionVerifier` (a `WorkBudget` of 4 signatures or 32 descriptors; the step's own CPU
  was 65 of 4,152 samples, the rest the flush), ≈16% `admission::stage` saving every hinted
  author's head and headers whether or not held, ≈8% the private Session pull that runs with
  each sync. `offer_inventory` re-offers every hint that is not `held`, and a held one again when
  `missing_page` finds a position within the last page, so an author whose missing bodies no
  peer holds any more (his rooms are sparse: 200, 188 and 76 of one room's entries on three
  nodes) is pulled again from every peer every period: 3.67 syncs per second over 39 peer-room
  pairs, a median 11 s between two syncs of one pair, about 370 commits per sync.
  Merge RCA (2026-10-22): role-complete receipts required moving sparse effect completion after
  semantic projection. The old operation had also made the sparse entry discoverable, so moving
  it exposed two circular dependencies: Presence demanded its own exact published position before
  it could publish that position, while Content retention/render tried to look the entry up only
  through the still-unsettled public index. Both parents worked only because they completed every
  effect early. The composed rule is exact: non-Content may stage its completed marker before its
  semantic handler only in the same atomic Batch, so a handler failure rolls the marker back;
  Content remains incomplete until the selected body is semantically admitted, and its retention
  and expiry decisions consume the transaction's already-authenticated exact entry rather than
  pretending it was settled. They preserve the source publication's sealed earliest first-seen
  fact across every deferred retry and restart. A deferred or unavailable body therefore commits
  neither a false receipt nor a public effect marker, and cannot extend its retention lifetime by
  retrying. The shipped proof binds its Content verdict to one exact accepted entry hash observed
  at Bob's effect outcome and then performs one `vox room read`; a polling read may not relabel a
  later unrelated refusal as this defect.
- **FX-30.** What a person would lose MUST survive a crash of the daemon, of the machine, or a
  power loss: a node's own entries, consent, trust, keys, Session records and the format marker
  are on disk before the command that wrote them returns (ruled 2026-10-20: "only what a person
  would lose (own entries, consent, trust, keys, Sessions, the format marker) gets the full
  flush to disk", "correct"). Derived sync state (held heads, cursors, verifier contexts, live
  windows) MAY be lost in such a crash, and after one the daemon MUST rebuild what it lost from
  the proofs it holds and from the peers it can reach, so the room syncs on. A sync round that persists only derived state MUST make no full flush:
  `vox status --json` names the daemon's count of full flushes, and over a quiet minute it MUST
  NOT move. Decision: derived state commits at redb `Durability::None` (redb 4.3.0 has no
  `Eventual`; a later durable commit carries it) and the ruled set stays `Immediate` however it
  arrived: a received consent, trust change, key package or Session record is flushed like the
  node's own.
  Any other received entry commits with the derived state that admitted it and reaches disk
  with the next durable commit, before this node acknowledges holding it to its sender (ADR-028
  R-6), so a crash in between loses only what the sender has not yet seen acknowledged and
  offers again. Measured cause, the same daemon: every `Batch::commit` is redb `Durability::Immediate` →
  `sync_data` → `fcntl(F_FULLFSYNC)` (vox-core never calls `set_durability`); the process spent
  0.65 thread-seconds per wall second inside `F_FULLFSYNC` (about 0.5 ms per call back to back;
  an isolated 8 KiB probe cost 7.6 ms), and that flush was most of the 1,367 commits' cost.
- **FX-31.** A flush to disk of one commit MUST NOT delay what does not depend on it: while a
  flush is held (apparatus: the store's flush stalled by a `VOX_TEST_*` knob of the `test-knobs`
  build, the way every held-step proof here stages a stall), the daemon's status
  publication, a member's read in that room, a post in that room or any other, and attention
  selection MUST answer within FX-17's bound ("publications, reads, posts and attention never
  wait on" a flush, ruled 2026-10-20: "sounds right"), and `vox status` MUST NOT say "room
  publication is busy" for a room whose only activity is a flush. Decision: no commit's flush
  runs while the room's lock is held; a post's batch is written under the lock and its own
  flush completes after the lock is released, so the post is accepted, and durable, within the
  bound while an earlier flush is still held. Measured cause, the same daemon: every commit ran inside `history_write` with
  the room mutex held (the `read_charged` closure owns the `lock_owned()` guard), so the daemon
  log said `room publication is busy; retry this operation` 424 times and `attention selection
  remains pending`, and the app's member list flickered (#983).
- **FX-32.** A node that finds a member holding more of its own feed than it does (a restored
  older profile, ADR-037 R5) MUST recover its own entries from that member, each verified under
  its own key and chain, and MUST keep reading meanwhile, the history it holds and the posts
  that arrive: "yes can supplement if signed/done correctly" (the decider, 2026-10-19). Its
  writes MUST stay refused until its own feed is current again and MUST resume then. Measured
  before this: a restored node refused its writes correctly and never read the member's next
  post (the restarts proof, step 5, 2026-10-19).
- **FX-33.** A change to a room's retention MUST NOT stop the room: after the admin shortens
  it, every member MUST still read and post there, the rows the member holds that are older
  than the new lifetime MUST expire on it, and no daemon MUST say it cannot save because of the
  sweep that change started. A room's recovery after a failed save MUST NOT impair the node's
  other rooms: while one room recovers, and when its recovery fails, every other room of the
  node MUST still read and post, and `vox status` MUST still answer. Decision: the recovery
  re-saves the room's sealed state in an ordinary write transaction on the store as it is
  open, never by closing and reopening the node's store file; the sweep prunes what the node holds; a signed-format
  entry is never a legacy Session; an entry whose body never arrived, or that sits past its
  author's verified head, is skipped that sweep and is not evidence of a malformed store; a row
  the sweep cannot classify (a Session step or a message) expires under the message lifetime,
  the longer of the two, once it is older than that, so nothing is kept forever for want of a
  classification. Measured cause, 2026-10-20 (the
  decider's node, vox 0.4.9, its daemon log `.daemon/log` at 2026-10-21T00:00:11Z): he set his
  repo room's retention from forever to one week in the app; the next sweep's legacy Session
  classification (`legacy_kind_in`) refused a format-2 entry as "Session classification source
  unverified", the room was poisoned, and the app said "vox cannot save: store save room:
  malformed at-rest artifact … It recovers by itself when writes succeed again", which it
  cannot while every tick's sweep hits the same entry; the same log shows two earlier sweeps
  that day (19:32:57Z and 23:21:31Z) poisoning rooms with "retention entry missing" (a body
  never received has no first-seen fact), cleared when the room was reopened (23:21:35Z). At
  00:15:30Z the poisoned room's recovery closed robert-work's whole store to reopen it
  writable; redb refused the reopen while another handle in the daemon was alive, the fallback
  left the store read-only or closed, and from then on every room of the node answered "the
  store is read-only until the identity is unlocked" or "the store is being reopened" on each
  one-second retry, for hours, until a restart: the app, `vox status` and the hooks got no
  answer from the daemon.
- **FX-34.** Unlocking a node is not remembering it. `vox node unlock` with a passphrase typed
  at the terminal, read from stdin or taken from `VOX_IDENTITY_PASSPHRASE` MUST make the node
  Ready for this daemon's life on every system, and the Locked status line MUST name a command
  that works. Where the system has a credential store Vox uses, the Keychain on macOS
  (ADR-028 K-10), `vox node unlock` MAY also remember the node there and MUST say so, and `vox
  node lock` MUST forget it. Where there is no such store, Linux today, `vox node unlock` MUST
  NOT persist the passphrase anywhere and MUST say that a daemon restart will ask again; a node
  Locked after a restart is unlocked again by hand, which the decider accepts ("that's ok as
  long as I can actually unlock them", 2026-10-21), so no Linux credential store is built for
  now. Vox MUST remember a plaintext passphrase file only by the path the person named with
  `--passphrase-file` (it copies nothing), and MUST never write one on its own. "I'm not saying passphrases should be stored,
  but there has to be a way to unlock a node"; "at least put the files in a correct place" (the
  decider, 2026-10-21). Measured cause, 2026-10-21 (the decider's Linux host, Ubuntu 26.04, vox
  0.4.9): after `vox update` restarted the daemon, the three nodes attached from typed
  passphrases on 10-19 came back Locked, and every unlock without a persistent file (typed,
  stdin, the environment variable) was refused with "node … cannot be remembered from a typed
  passphrase, an environment variable or stdin on this system; save its passphrase in a private
  persistent file", while the status line said "Unlock with vox node unlock …": the product's
  advice looped into its refusal. Introduced by 6d9f286fa (2026-10-13), shipped in v0.4.5
  through v0.4.9; the Keychain path hid it on macOS.
- **FX-35.** A full daemon-wide flow-state pool MUST NOT keep an eligible port from starting a
  bounded-sync round while any charge of that pool is held by a flow that is not running a
  round. Terms: a port is eligible when it has a need (ADR-037 R7: a raised request or a head
  newer than it served), a connection to its peer and no bounded-sync round running for that
  port; a flow is parked while it sits in `ready`, `deferred`, `retiring` or `cleanup` and no
  task runs it. The flow-state pool is shared by every hosted node, each charge is 128 KiB, and
  its limit MUST be exactly `2 × active-or-retiring hosted node identities`, with no fixed or
  minimum floor. Current and retiring generations of the same identity count once. Across those
  generations each identity MUST run at most two bounded-sync rounds at once, so the pool exactly
  covers the maximum legal running work. Each running bounded-sync round MUST hold exactly one
  flow-state charge, and
  each held flow-state charge MUST be held by exactly one running bounded-sync round.
  Acquisition of the charge and the round's transition to running MUST be one atomic state
  transition for accounting and status; every transition out of running, by completion, failure
  or cancellation, MUST release the charge. A flow in `ready`, `deferred`, `retiring` or
  `cleanup`, a flow shelved without starting a round, and an exact continuation retained while
  waiting for a charge MUST hold no worker, byte charge, outbound slot or flow-state charge. So
  the pool bounds rounds running at once, never flows at rest. Each node's bounded controller
  MUST retain at most twelve flows in all across `ready`, `running`, `deferred`, `retiring` and
  `cleanup`.

  The node actor retains parked `Flow` work; the daemon-wide pool retains only its admission-order
  metadata. Exhausting one identity's two running positions is the legitimate
  `flow_state_node_busy` refusal. A global `flow_state_pool_full` refusal is an impossible invariant
  violation under the legal running-work limit above, and MUST NOT replace node-busy. If it
  nevertheless occurs, the daemon MUST retain that exact `Flow` as an event-owned continuation,
  release every worker,
  byte, room, lane-job, live-flow, outbound-slot and flow-state reservation the failed attempt
  acquired, and record its eligibility in monotonically increasing order. The exact transition
  of a running round out of `running` that releases a charge MUST select and wake the earliest
  retained eligible continuation before a new contender can reserve that charge; a continuation
  that has ceased to be eligible MUST be removed immediately. Vox MUST NOT discard or
  reconstruct the work, create a need from a hint the node already holds, or depend on a tick,
  retry, timer or polling pass to wake it. No count or threshold of periods, turns, elapsed time,
  retries, retained continuations, CPU use or machine load MAY dispose, expire, refuse, retire,
  defer, delay, skip, space or reorder that work. A timeout or connection failure MAY end a
  running round; only its transition out of running releases the charge and causes the next
  eligible continuation to run. Registering or unregistering a hosted identity MAY resize the
  accounting limit but MUST NOT grant or wake a continuation. If a charge release races the
  refusing Flow's enrollment, an unforgeable release-edge identity MAY carry that exact causal
  edge across enrollment; a resize, tick or unrelated actor event cannot create such an edge.

  A start attempt is one scheduler invocation for an eligible port, including its flow-state
  reservation; it ends `started` only when it launches the bounded-sync round, otherwise
  `not_started`. `vox status --json` MUST report, for every port under
  `lanes.ports[]`: `start_outcome`, equal to `never_attempted` until the first start attempt in
  the current daemon process ends and thereafter equal to `started` or `not_started` for the
  most recently ended attempt (an in-progress attempt does not replace that value, and a daemon
  restart resets it to `never_attempted`); `start_reason`, present if and only if
  `start_outcome` is `not_started`, where the gates MUST be tested in the following order and
  `start_reason` MUST equal the first gate that fails: `room_busy` (the room's state could not
  be taken without waiting), `archive_budget_busy` (an archive port only: the archive-lane job
  could not be reserved), `control_budget_busy` (the control-lane job could not be reserved),
  `live_lane_busy` (the node's live flow slot holds another flow), `no_outbound_slot` (the
  outbound slot could not be taken), `flow_state_node_busy` (the fingerprint's two source-owned
  running slots are held across its current and retiring actor generations) and
  `flow_state_pool_full` (every daemon-pool position is occupied by a running charge or by an
  earlier release-edge grant), `flow_state_pool_overcommitted` (`occupied > limit`, never
  misreported as exact fullness), `flow_state_owner_missing` (the admitted worker no longer belongs
  to a pool actor generation), and `flow_state_order_exhausted` (the process-lifetime monotonic
  continuation identity space is exhausted); and the
  boolean `round_running`, true while a bounded-sync round of that port runs. A node-busy
  refusal MUST NOT be reported as pool-full: `flow_state_node_busy` is possible while
  `in_use < limit`, whereas `flow_state_pool_full` requires `occupied == limit`. It MUST report
  the pool under `lanes.budget.flow_state` as the integers `in_use` (running charges), `promised`
  (release-edge grants not yet consumed by their actors), `occupied` (`in_use + promised`), and
  `limit` and, under `by_node` and `occupied_by_node`, objects with exactly one member per hosted node, keyed by
  that node's node ID, whose value is that node's integer in-use count; the member values MUST
  sum to `in_use` and `occupied` respectively; a node's `round_running` values and its own `by_node` member MUST be taken
  from one snapshot, and that member MUST equal the number of that node's ports whose
  `round_running` is true. While at least one port in a room has a retained flow-state
  continuation waiting for the exact release edge, any "no completed sync" text shown for that
  room in `vox status` or in the app MUST contain the literal text `flow-state pool`; when no port
  in the room has such a continuation, that text MUST NOT identify the flow-state pool as the
  cause. Before the stale threshold, that exact retained ownership is already an unhealthy
  `room-flow-state-pool:<room>` condition: diagnosis MUST name it immediately rather than wait on
  elapsed time, and MUST NOT attach it to another room. Measured cause,
  2026-10-21 (UTC, as every date in this record): on the decider's daemon (four hosted nodes,
  three rooms, restarted 02:32Z) every port of every node had started no round, `queued` froze,
  every room said "no completed sync in 10 minutes", and posts moved neither between the two
  Macs nor between two nodes of one daemon while the daemons were connected; in the #986 staging
  on main bb4062651, instrumented, every port was eligible, popped and re-queued each pass with
  `start_bounded_outbound` returning false at `reserve_flow_state` 370,156 times in one run, the
  pool full (16 of 16) by the first fifth of the run with 1,951 flows started before and none
  after, the outbound slots 0 of 16 in use and the archive lane empty throughout. The product
  said only the symptom. "please make vox work"; "be methodical" (the decider, 2026-10-21).

  > **Decision amendment (the decider, 2026-10-23).** The pool limit is exactly
  > `2 × active-or-retiring hosted node identities`, with no fixed or minimum floor; generations
  > of one identity share its two running positions. Parked work retains its exact actor-owned
  > `Flow` but no worker, byte charge, outbound slot or flow-state charge. This replaces the
  > earlier `max(16, 2 × hosted identities)` formula; the causal release and retention requirements
  > above remain. Historical 16-of-16 measurements describe the defect, not the capacity policy.


  Implementation RCA, 2026-10-24. Running capacity is not the only resource dependency. A
  Control history request could retain a foreground worker through an `Incoming` or `Held`
  buffer, then ask its original Control-job alias for another foreground worker. Inventory,
  metadata verification, header reconstruction, Entry, Proof and Chunk-authority paths shared
  this pattern.
  Thirty-two Entry requests could retain two 128-KiB metadata workers each, occupying all 64
  foreground positions with only 8 MiB of metadata, then all wait for a third worker. This is
  a source-reachable cycle, not the cause established by the sampled 16-node journey. The
  operation is to carry its actual admitted worker through overlapping reads and account their
  full simultaneous byte peak; dropping a job variable does not release a worker still owned
  by a charged buffer. Increasing a cap or waiting longer does not repair this dependency.

  Local capacity, peer Busy and transport failure have different owners. For an owned outgoing
  Flow, local capacity is to retain the exact operation behind the real local release; `SessionBusy` or `NotYetMember`
  from a peer is to retain the exact wire continuation under the existing Busy policy, with
  no invented cross-host release event. A fresh wire attempt does not discard verified partial
  reception. Required capacity refusal before I/O is to reach the first reset owner as typed
  capacity and use `SessionBusy`, not misreport a transport failure. Protocol, storage, epoch
  and authority failures retain their own fences and outcomes; this is not a retry-everything
  rule. These changes do not alter the approved two-position capacity or receipt semantics.

  The same composed journey first exposed a late completion reservation that poisoned an
  ordinary room read, an announcement that needed a new retained position while all existing
  positions were occupied, and private requesters that could consume capacity needed by their
  responders. The candidate is
  to prepay record/completion and ACK resources before semantic mutation, keep announcement
  priority separate from the original Flow's ownership, and reserve the full private Page/apply
  peak with its derived serving dependency inside the existing total. An identical validated
  checkpoint has no new fact to seal or commit. Retirement is to distinguish actual progress,
  byte/publication dependencies and failed storage, join real workers, and erase the exact old
  secret-bearing capabilities; a timer or unrelated node's recovery cannot manufacture cleanup.

  Evidence remains separate from these source corrections. The `3c15d2174` journey accepted all
  32 initial posts and completed all 480 cross-member read observations, then ended APPARATUS
  during archive setup: its fixture derived roughly 16 MiB of room text from the generic log
  payload bound, while Content text is limited to 64 KiB and the IPC frame to 256 KiB. Real job
  barriers, not body size, establish that proof's flow-state pressure; legal short posts are to
  replace both oversized fixtures without changing its release/read assertions. This is not a
  completed journey or a byte-pressure mutant result. Independent peer-source comparison and
  the detailed ownership/runtime RCA are recorded on [#1028](https://github.com/robertelee78/vox/issues/1028#issuecomment-6377582483).


  A subsequent `8c9832ab3` run accepted the same 32 posts but did not complete delivery before
  the lead stopped it on diagnosed product smoke. Two public observations showed no change in
  completed rounds, body/history work or either room's readable rows while 819 additional
  SessionBusy failures accumulated. Workers were briefly active between observations; the
  samples do not establish a permanently empty worker pool. The admission number in status is
  a wake token, not the fair ticket's sequence, and is not evidence of ticket grants or FIFO
  head progress.

  The retained Control admission could name a different port than the locally selected ready
  Flow. A candidate could queue or consume a worker before discovering its local live lane was
  occupied. Selection is to make that exact retained owner runnable first, preserving the whole
  displaced Flow, or withdraw only its own unusable resource ticket while retaining its logical
  request/hint. Read-only readiness observation is to preserve the documented first-gate reason;
  only real admission grants capacity. A diagnostic root label can change from inventory to hint
  while waiting and MUST NOT replace the actual ticket identity of room, peer and lane.

  Independently, Busy bypass used semantic completion to detect a fresh published generation.
  A refused attempt correctly completes nothing, so an unchanged unfinished generation could
  bypass the existing Busy policy repeatedly. Actual foreground attempts are to consume separate
  scheduler-only generation credit at launch. A newer generation arriving during the attempt
  retains fresh credit; no request, peer receipt or semantic completion is manufactured. An
  archive-only Page, private pull or incoming attempt does not spend live foreground credit;
  a normal legacy full-sync attempt does, regardless of its resource lane. This changes no
  retry duration or running-capacity policy. The [follow-up RCA](https://github.com/robertelee78/vox/issues/1028#issuecomment-6378076112)
  distinguishes measured observations, source causes and the still-required working journey.
- **FX-37.** A software root signer MUST retain the ML-DSA signing key constructed from its
  seed and MUST reuse that key's cached public and expanded signing material. Asking the signer
  for its public key or a signature MUST NOT reconstruct the signing key from its seed. The
  retained library `SigningKey` MUST keep its existing zeroize-on-drop behavior; Vox MUST NOT
  make the containing secret clonable; encrypted backup MUST copy the same seed directly from
  that key into zeroizing memory; the fingerprint, public-key bytes, deterministic signature
  behavior and restored identity MUST remain seed-identical. The one expansion already performed
  during signer construction remains; FX-37 removes per-operation reconstruction and does not
  claim that construction performs no work on a Tokio worker.

  Measured cause, 2026-10-21: the shipped-binary room journey failed twice on exact FX-14
  candidate `48e8daccd2c80010fcc21dc274003c03cb5e4331` and once on untouched `origin/main`
  `7fb5a8068a3aeb36589fac73155e415bde3d5f2a`. In every run `vox room create` lost a Ready
  daemon to `tokio-rt-worker has overflowed its stack`; each run used fresh explicit scratch
  data and config roots and began below machine load 6. LLDB stopped at the guard page with the
  exact product path `finish_create_channel_unboxed` → `Node::publish_channel_locally` →
  `NodeNet::own_records` → `RendezvousRecord::build` → `CompositeSecret::sign` →
  `CompositeSecret::ml_dsa_key` → `ml_dsa::SigningKey::from_seed` → ML-DSA expanded-key
  verification-matrix cloning. The signer kept only its 32-byte ML-DSA seed and repeated that
  expansion for every signature. On unchanged main, giving the process a 16 MiB worker stack
  made the same journey pass; that isolates finite stack exhaustion but is diagnostic evidence,
  not a fix. A larger worker stack, quota, pacing delay or timeout MUST NOT substitute for
  removing the repeated expansion. The shipped debug daemon on its normal runtime MUST create a
  room, post, read the post and remain running. An isolated mutant that restores per-sign key
  reconstruction MUST turn that room-create claim PRODUCT red with the reproduced worker-stack
  overflow.

## Unchanged rulings

The decider confirmed these on 2026-10-19 ("that still sounds right to me"): no human/agent
typing, only nodes; trust per direction; no rate limits; retention is look and feel, not
security; Vox never spawns harness instances; GitHub through awa is the scoreboard and the room
is coordination only.

## Superseded and amended lines

Narrow successor amendments. Requirements not named here remain in force.

| Existing rule | Amendment |
|---|---|
| ADR-031 LT-7: nothing automatic for nodes on other machines; `vox room join` tells the person to `trust add` each member | For two computers of the person, daemon trust is the path the product offers first (FX-1, FX-6); per-node trust is the exception for other people's nodes |
| ADR-035 CT-6: the primary flow begins with Add Computer in Vox.app | Preserved; FX-6 adds that every surface where two of the person's daemons first meet names it, and FX-5 that the headless command is a first-class path |
| ADR-029 SE-1–SE-5, ADR-031 HK-1–HK-6, NC-1–NC-6 and RM-1–RM-6, ADR-033: an agent node joins the repo room by itself and is a member | Preserved; membership is not presence (FX-8–FX-10); every listing shows Sessions per node (FX-9) |
| ADR-020 6.8 (V030-15): a wake is an announce-only notice of urgent messages and replies; 6.15: ordinary conversation arrives through the per-turn drain | An idle harness window shows every new message as it arrives (FX-12); the drain stays the record of what the model read |
| ADR-020 4.11 (the ask and answer vocabulary) | An undirected ask is answered per Session that finds it relevant, without cross-replies; an addressed ask by its addressee (FX-13) |
| ADR-036 legacy history recovery (Legacy history required, resume, cancel, cached-only reads) | Deleted (FX-18) |
| ADR-037 R7, R11: event-driven gates; a turn may run several chunks, never a cycle | FX-15 adds: no round without a nameable need; a no-progress, no-wait round retires; a hint for a held head finishes on arrival |
| ADR-037 R5: a member's higher own head marks the room "own history behind"; every write refuses until resolved | FX-32 says what resolves it: the node recovers its own entries from that member (verified under its own key), keeps reading, and writes again once current |
| ADR-035 CT-9, CT-14: computer-trust changes are reconciled, idempotently and recoverably | Preserved; FX-28 adds the bound: a change made on either daemon shows on every attached node of both within 5 s, or within 60 s after the peer is reachable again when its exchange was lost; an unchanged pair starts no exchange except the named fallback and derives no binding again |
| ADR-037 R7, R11: a port runs a round only on a need; a turn may run several chunks, never a cycle | Preserved; FX-29 adds what a round that brings nothing may write: nothing |
| No predecessor: no ADR names a durability class for the store or a flush under a room's lock | FX-30 and FX-31 are new rules |
| PRD-001 R7, R8; ADR-023 M23.1: the admin sets the room's retention; it applies to what is stored at the next sweep | Preserved; FX-33 adds that the sweep never stops the room |
| ADR-028 K-10, ADR-031 CW-2, CW-7: a node unlocked at a terminal is remembered in the Keychain so the daemon makes it Ready at each start | Preserved where a credential store exists (the Keychain); FX-34 adds that unlocking never depends on remembering, that Linux remembers nothing for now, and that Vox never writes a passphrase file on its own |
| ADR-037 R7, R11; ADR-026: a bounded flow keeps its state between turns, within a daemon-wide pool | FX-35 adds that a flow-state pool charge is held only while a round runs, so the pool never accounts for flows at rest (nothing is disposed by time), and that the latest start attempt's outcome is reported for every port |
| No predecessor: signer construction reconstructed the expanded ML-DSA key to derive its cached public key, and every signature reconstructed it again | FX-37 retains the zeroizing library signing key built from the seed and reuses its cached public and expanded signing material; a larger worker stack or an elapsed-work workaround is not the fix |
| ADR-034 §5 "Health is true" (HL-1, HL-2), PRD-001 R35 | The lane's completed rounds are completed syncs (FX-16); the control socket answers under sync load (FX-17) |

## Implementation order and related work

1. FX-15, FX-16, FX-17: the daemon's idle cost and truthful status; first cut (v0.4.7).
2. FX-18: delete legacy recovery; same cut or the next.
3. FX-6, FX-7, FX-4, FX-5, FX-2, FX-3: daemon trust as the obvious path, verified on two daemons
   in two data roots, then on the VM pair.
4. FX-11's design story, then FX-8–FX-10 in the app, the CLI, the hook and the skill pack.
5. FX-12, FX-13, FX-14: the idle window, asks per Session, `--re` prefixes.
6. FX-20's walkthrough runs from the first cut on; its defects join the queue as found.
7. FX-24, FX-26, FX-27, FX-23, FX-22, FX-25: the daemon's CPU under real rooms, measured on
   the decider's daemon on 2026-10-20, in that order (the trigger, the cipher, the design, the
   symbols); one cut (v0.4.8).
8. FX-28, FX-29, FX-30, FX-31: the idle daemon's disk and CPU, measured on the decider's
   daemon (v0.4.9) on 2026-10-20, in that order (the tick, the re-pull, the flush, the lock);
   FX-32 under #934; FX-33 and FX-34 with them; FX-35 first among them, since until it lands
   the reproduced four-node daemon syncs nothing; one cut (v0.4.10).
9. FX-37 is an immediate cross-cutting v0.4.10 blocker: until the normal shipped daemon can
   create a room, every room journey that reaches creation is red regardless of its own change.

Each ADR change under this record is reviewed by an independent session (opencode-work) before
its stories are extracted.

## Consequences

### Positive

- Two of the person's computers meet once; every node on both reads every other, the app-bound
  nodes drive the agents, and no keyring is edited by hand.
- A room's roster says who is really there: which Sessions, on which node.
- An idle Vox is idle, and a red banner is true.
- Creating and publishing a room reuses already-constructed signing material instead of risking
  the daemon on each signature.

### Negative

- Delivering into idle harness windows through tmux ties Vox to how the person runs harnesses;
  it is explicit and per harness.
- Deleting legacy recovery orphans rooms created before v0.4.5; the decider accepts that.
- A software signer retains expanded ML-DSA secret material for its lifetime. The seed already
  carries the same cryptographic authority, and the library zeroizes both on drop; the tradeoff
  is additional resident secret memory in exchange for bounded stack use on every signature.

### Neutral

- Daemon identity and trust are ADR-035's; this ADR changes where the product offers them and
  what it says, not the contract.

## Links

- ADR-018 (proofs), ADR-020 (agent comms), ADR-025 D7 (periodic request), ADR-029 (Sessions),
  ADR-031 (agent nodes join by themselves), ADR-033 (the repo room), ADR-034 (true health),
  ADR-035 (computer trust), ADR-036 (live messages and requested history), ADR-037 (convergence).
- Release milestone v0.4.7 (#14) and the following small releases.
