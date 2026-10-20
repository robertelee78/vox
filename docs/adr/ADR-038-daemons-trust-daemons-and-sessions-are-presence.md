# ADR-038: Daemons Trust Daemons, and Sessions Are Presence

- **Status**: Proposed, after v0.4.6. The decider's product rulings of 2026-10-19 (one question
  at a time, quoted below) are the requirements; nothing here is built. Each requirement lands
  with its proof (ADR-018) in a small release (FX-19).
- **Date**: 2026-10-19; amended 2026-10-20 (FX-22–FX-27, the daemon's CPU)
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
  FX-27) lands with a proof that drives the shipped `vox` binary as a person would, with a
  mutant that turns it red on its own assertion (ADR-018). The two-computer requirements
  (FX-2–FX-7) are proved by two daemons in two data roots on one machine. FX-11's design, FX-19,
  FX-20 and FX-25 are process rulings: FX-19's record is each closed release milestone, FX-20's
  is the walkthrough's defect record, FX-11's is the amendment it produces, and FX-25's is each
  release's asset list.
- **FX-22.** A governance question about a room (who may read whom, who has consented, what a
  member offers) MUST cost no store read and no decrypt when the room's governance has not
  changed since the question was last answered. Decision: the room keeps its folded consent facts
  in memory as a semantic projection (per author, the readers it consented to and its reset
  sequence), never a store snapshot, page or row vector, so the index's bounded-turn rule
  stands; the sealed index remains the only durable representation, and a restart loads the
  projection from the index and the entries it names, never by replaying the log. Measured
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
- **FX-24.** A preparation turn in which the step did no work MUST end as a wait on the thing the
  step waits for, in the words `vox room list` and the app show; a wait is the only other way a
  turn ends, so such a turn is never recorded as progress. Measured cause,
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
  rule that counts turns or measures CPU time. FX-15 stands unchanged as the one retry schedule:
  a repeated wait on the same thing outside the turn is retried at that wait's own pace, and a
  turn that did work with a nameable need still pending is followed at once; a quiet room runs
  nothing. Ruling: "caps on cpu seem like … footguns", "we need to understand
  what is driving the cpu inefficiency rather than capping the cpu" (the decider, 2026-10-20,
  rejecting a ten-fast-turns-then-one-a-second cap proposed for FX-24's cause).

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

Each ADR change under this record is reviewed by an independent session (opencode-work) before
its stories are extracted.

## Consequences

### Positive

- Two of the person's computers meet once; every node on both reads every other, the app-bound
  nodes drive the agents, and no keyring is edited by hand.
- A room's roster says who is really there: which Sessions, on which node.
- An idle Vox is idle, and a red banner is true.

### Negative

- Delivering into idle harness windows through tmux ties Vox to how the person runs harnesses;
  it is explicit and per harness.
- Deleting legacy recovery orphans rooms created before v0.4.5; the decider accepts that.

### Neutral

- Daemon identity and trust are ADR-035's; this ADR changes where the product offers them and
  what it says, not the contract.

## Links

- ADR-018 (proofs), ADR-020 (agent comms), ADR-025 D7 (periodic request), ADR-029 (Sessions),
  ADR-031 (agent nodes join by themselves), ADR-033 (the repo room), ADR-034 (true health),
  ADR-035 (computer trust), ADR-036 (live messages and requested history), ADR-037 (convergence).
- Release milestone v0.4.7 (#14) and the following small releases.
