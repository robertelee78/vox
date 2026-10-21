# ADR-038: Daemons Trust Daemons, and Sessions Are Presence

- **Status**: Proposed, after v0.4.6. The decider's product rulings of 2026-10-19 (one question
  at a time, quoted below) are the requirements; nothing here is built. Each requirement lands
  with its proof (ADR-018) in a small release (FX-19).
- **Date**: 2026-10-19; amended 2026-10-20 (FX-22–FX-27, the daemon's CPU); amended
  2026-10-20 (FX-28–FX-34: the idle daemon's disk and CPU, measured on v0.4.9, the own-feed
  recovery ruling of 2026-10-19, a retention change that poisoned a room, and a node on Linux
  that could not be unlocked); amended 2026-10-21 (FX-35: a daemon whose parked flows held
  the flow-state pool synced nothing); amended 2026-10-21 (FX-37: room creation overflowed a
  normal Tokio worker stack while reconstructing an ML-DSA root key for one signature)
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
  member offers) MUST read nothing from the store but the governance index's header, and decrypt
  no fact or entry, when the room's governance has not changed since the question was last
  answered. Decision: the room keeps its folded consent facts in memory as a semantic projection
  (per author, the readers it consented to and its reset sequence), never a store snapshot, page
  or row vector, so the index's bounded-turn rule stands; the index header's revision, which
  moves with every change to the index, says whether the projection is current, so no
  in-process bookkeeping can miss a write; the sealed index remains the only durable
  representation, and a restart loads the projection from the index and the entries it names,
  never by replaying the log. Measured
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
  period, after the peer becomes reachable again. Two daemons on which nothing changed
  MUST spend nothing on it:
  over an idle minute their CPU grows by no more than FX-15's quiet-room bound. "We need the
  detection of change logic to be sound. Easy for local daemon to notice, but daemon to daemon
  update needs to be solid" (the decider, 2026-10-20). Decision: a node's binding is derived
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
- **FX-30.** What a person would lose MUST survive a crash of the daemon, of the machine, or a
  power loss: a node's own entries, consent, trust, keys, Session records and the format marker
  are on disk before the command that wrote them returns (ruled 2026-10-20: "only what a person
  would lose (own entries, consent, trust, keys, Sessions, the format marker) gets the full
  flush to disk", "correct"). Derived sync state (held heads, cursors, verifier contexts, live
  windows) MAY be lost in such a crash, and after one the daemon MUST rebuild what it lost from
  the proofs it holds and from the peers it can reach, so the room syncs on. A sync round that persists only derived state MUST make no full flush:
  `vox status --json` names the daemon's count of full flushes, and over a quiet minute it MUST
  NOT move. Decision: derived state commits at redb `Durability::None` or `Eventual` (a later
  durable commit carries it) and the ruled set stays `Immediate` however it arrived: a
  received consent, trust change, key package or Session record is flushed like the node's own.
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
  task runs it; the flow-state pool is `RETAINED_FLOWS` charges per daemon (16 today, each 128
  KiB), shared by every hosted node. Decision: each running bounded-sync round MUST hold exactly
  one flow-state charge, and each flow-state charge that is held MUST be held by exactly one running bounded-sync round; acquisition of the charge and the round's transition to running MUST be
  one atomic state transition for accounting and status; every transition out of running, by
  completion, failure or cancellation, MUST release the charge; a flow in `ready`, `deferred`,
  `retiring` or `cleanup`, and a flow shelved without starting a round, MUST hold no charge. So
  the pool bounds rounds running at once, never flows at rest. Each node's bounded controller
  MUST retain at most twelve flows in all across `ready`, `running`, `deferred`, `retiring` and
  `cleanup`, and MUST run at most two bounded-sync rounds at once; the daemon-wide number of
  running rounds is therefore at most the smaller of `RETAINED_FLOWS` and twice the hosted
  nodes. When an eligible port cannot reserve flow state because every charge is held by a
  running round, the daemon MUST dispose the flow whose resume made that reservation attempt,
  MUST re-arm all and only work still outstanding under FX-29 without creating a need from a
  hint the node already holds, MUST release every room, lane-job, live-flow, outbound-slot and
  flow-state reservation the attempt acquired, and MUST re-queue the port with its need
  preserved. The port MUST then have exactly one entry in a daemon-wide first-come flow-state
  wait queue; it MUST retain that entry until it is selected or ceases to be eligible, and the
  daemon MUST remove it immediately when either occurs. Whenever a charge is available and at least one eligible waiter remains, the daemon MUST select the earliest-enqueued eligible waiter, remove its entry and run one start
  attempt for it before permitting a port not selected from that queue to reserve the charge; if
  that attempt ends before reserving the charge, the daemon MUST repeat this selection while a
  charge and an eligible waiter remain; ties in enqueue order MAY be broken arbitrarily. No
  count or threshold of periods, turns, elapsed time or CPU time MAY dispose, expire or defer a
  parked flow, or delay, skip or space a start attempt (FX-27); flow-state release MUST be
  caused solely by a round's transition out of running, which a timeout or a connection failure
  MAY cause. A start attempt is one scheduler invocation for an eligible port, including its
  flow-state reservation; it ends `started` only when it launches the bounded-sync round,
  otherwise `not_started`. `vox status --json` MUST report, for every port under
  `lanes.ports[]`: `start_outcome`, equal to `never_attempted` until the first start attempt in
  the current daemon process ends and thereafter equal to `started` or `not_started` for the
  most recently ended attempt (an in-progress attempt does not replace that value, and a daemon
  restart resets it to `never_attempted`); `start_reason`, present if and only if
  `start_outcome` is `not_started`, where the gates MUST be tested in the following order and
  `start_reason` MUST equal the first gate that fails: `room_busy` (the room's state could not
  be taken without waiting), `archive_budget_busy` (an archive port only: the archive-lane job
  could not be reserved), `control_budget_busy` (the control-lane job could not be reserved),
  `live_lane_busy` (the node's live flow slot holds another flow), `no_outbound_slot` (the
  outbound slot could not be taken) and `flow_state_pool_full` (every charge of the pool is held
  by a running round); and the boolean `round_running`, true while a bounded-sync round of that
  port runs. It MUST report the pool under `lanes.budget.flow_state` as the integers `in_use`
  and `limit` and, under `by_node`, an object with exactly one member per hosted node, keyed by
  that node's node ID, whose value is that node's integer in-use count; the member values MUST
  sum to `in_use`; a node's `round_running` values and its own `by_node` member MUST be taken
  from one snapshot, and that member MUST equal the number of that node's ports whose
  `round_running` is true. While at least one port in a room has an entry in the daemon-wide
  flow-state wait queue, any "no completed sync" text shown for that room in `vox status` or in
  the app MUST contain the literal text `flow-state pool`; when no port in the room has such an
  entry, that text MUST NOT identify the flow-state pool as the cause. Measured cause,
  2026-10-21 (UTC, as every date in this record): on the decider's daemon (four hosted nodes,
  three rooms, restarted 02:32Z) every port of every node had started no round, `queued` froze,
  every room said "no completed sync in 10 minutes", and posts moved neither between the two
  Macs nor between two nodes of one daemon while the daemons were connected; in the #986 staging
  on main bb4062651, instrumented, every port was eligible, popped and re-queued each pass with
  `start_bounded_outbound` returning false at `reserve_flow_state` 370,156 times in one run, the
  pool full (16 of 16) by the first fifth of the run with 1,951 flows started before and none
  after, the outbound slots 0 of 16 in use and the archive lane empty throughout. The product
  said only the symptom. "please make vox work"; "be methodical" (the decider, 2026-10-21).
- **FX-35. Decision (2026-10-21).** The daemon flow-state pool has no wait queue: its limit is exactly `max(16, bounded-sync running slots per node × currently hosted nodes)`, so registration precedes starts, unregister follows retired rounds, and the shared slots invariant makes pool-full unreachable without a timeout or periodic retry.

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
| ADR-035 CT-9, CT-14: computer-trust changes are reconciled, idempotently and recoverably | Preserved; FX-28 adds the bound: a change made on either daemon shows on every attached node of both within 5 s, or within 60 s after the peer is reachable again when its exchange was lost, and an unchanged pair spends nothing |
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
