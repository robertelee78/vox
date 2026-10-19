# ADR-038: Daemons Trust Daemons, and Sessions Are Presence

- **Status**: Proposed, after v0.4.6. The decider's product rulings of 2026-10-19 (one question
  at a time, quoted below) are the requirements; nothing here is built. Each requirement lands
  with its proof (ADR-018) in a small release (FX-19).
- **Date**: 2026-10-19
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
  promptly.
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
  through daemon trust.
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

- **FX-15.** A quiet room MUST run no sync round without a need the status can name. A round
  that made no progress and waits on nothing MUST retire its flow, never be retried at once; a
  hint for a head the node already holds MUST be finished on arrival, never turned into a round;
  the periodic request (ADR-025 D7) remains the only cadence. This is measured, not gated: no
  threshold is added to the product; a violation is reported to the decider with its
  measurement (ADR-037 R13).
- **FX-16.** `vox status` and the app MUST record each round the lane completes as the room's
  and the peer's last completed sync; "no completed sync" MUST fire only when it is true
  (ADR-034's true health; PRD-001 R35).
- **FX-17.** The daemon MUST answer its control socket within a harness hook's wait while it
  syncs; a hook that reports "the vox daemon here did not answer promptly" on an idle machine
  is a product defect.

### 5. No legacy

- **FX-18.** Rooms from before the v0.4.5 format are not supported: "we're still building vox
  and have no users -- I want to continue to design freely without overengineering backwards
  compat." The legacy history recovery flow (ADR-036's "Legacy history required", resume and
  cancel) MUST be deleted, with its prompts, states and proofs. An unsupported room MUST be
  refused with one sentence naming what to do (leave it and create a new one). Real data MUST
  NOT be deleted or reset by Vox.

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
- **FX-21.** Every requirement above lands with a proof that drives the shipped `vox` binary as
  a person would, with a mutant that turns it red on its own assertion (ADR-018). The two-
  computer requirements (FX-2–FX-7) are proved by two daemons in two data roots on one machine;
  the walkthrough is the person's proof.

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
| ADR-029 SE-1–SE-5, ADR-031 LT-1–LT-5, ADR-033: an agent node joins the repo room by itself and is a member | Preserved; membership is not presence (FX-8–FX-10); every listing shows Sessions per node (FX-9) |
| ADR-020 §4 and the 2026-10-01 wake decision: wakes announce urgent messages only; the text arrives through the per-turn drain | An idle harness window shows every new message as it arrives (FX-12); the drain stays the record of what the model read |
| ADR-020 §3 ask/answer | An undirected ask is answered per Session that finds it relevant, without cross-replies; an addressed ask by its addressee (FX-13) |
| ADR-036 legacy history recovery (Legacy history required, resume, cancel, cached-only reads) | Deleted (FX-18) |
| ADR-037 R7, R11: event-driven gates; a turn may run several chunks, never a cycle | FX-15 adds: no round without a nameable need; a no-progress, no-wait round retires; a hint for a held head finishes on arrival |
| ADR-034 true health, PRD-001 R35 | The lane's completed rounds are completed syncs (FX-16); the control socket answers under sync load (FX-17) |

## Implementation order and related work

1. FX-15, FX-16, FX-17: the daemon's idle cost and truthful status; first cut (v0.4.7).
2. FX-18: delete legacy recovery; same cut or the next.
3. FX-6, FX-7, FX-4, FX-5, FX-2, FX-3: daemon trust as the obvious path, verified on two daemons
   in two data roots, then on the VM pair.
4. FX-11's design story, then FX-8–FX-10 in the app, the CLI, the hook and the skill pack.
5. FX-12, FX-13, FX-14: the idle window, asks per Session, `--re` prefixes.
6. FX-20's walkthrough runs from the first cut on; its defects join the queue as found.

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
