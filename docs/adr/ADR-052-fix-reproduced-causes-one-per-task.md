# ADR-052: v0.4.31 Fixes Reproduced Causes, One per Task

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-20) for v0.4.31 by the decider (ruling 8), after an independent
  review by GLM-5.3 whose one P1 and seven P2 findings are answered in this text. It records
  his rulings of 2026-11-20, listed below, and replaces ADR-040 to ADR-050 and
  `docs/release/v0.4.31.md` as what v0.4.31 builds. Its tasks are tracked in their own GitHub
  Project, in milestone v0.4.31. Nothing in it is built: each requirement is to land with its
  proof, and implementation, acceptance and delivery are recorded on the source-bound issues,
  separately from decision status.
- **Date**: 2026-11-20
- **Deciders**: Robert E. Lee
- **Tags**: stabilization, root cause, KISS, join, trust, sync, agents, status, restart, install,
  store, release
- **Supersedes**: for v0.4.31, ADR-040, ADR-041, ADR-042, ADR-044, ADR-045, ADR-046, ADR-047,
  ADR-048, ADR-049, ADR-050, and ADR-043 except CJ-11, CJ-12 and CJ-17
- **Related**: ADR-007, ADR-012, ADR-018, ADR-023, ADR-029, ADR-035, ADR-043, ADR-051
- **Source**: the evaluation of the 85 tasks of `docs/release/v0.4.31.md`, one verdict per task
  (`regroup/report.md`, `regroup/ledger.md` and `regroup/components/` in the release's evidence
  archive, `/opt/vox-evidence/v0431/`); the reports and receipts named with each cause, in the
  same archive; code read at tag v0.4.30 (commit `8d71ab337`). Nothing was run for this ADR.
  Line citations are the evaluation's; those for C-1 to C-9 were read again while writing it.

## What this ADR sets out to do, and the rulings it carries

**The goal.** People and agents in a room read each other, while agents post all day, a member
is slow, someone joins late, a computer is added, and the daemon is restarted or updated. Each
requirement below removes one cause that was reproduced, with the smallest change that removes
it, and is accepted on a proof that was red before the change.

**The decider's rulings this ADR carries** (2026-11-20; quoted words are his):

1. The 85-task plan is not built. "85 open tasks seems .. like we're throwing darts at the wall
   -- none of that convinces me we know the true root cause ... none of that convinces me we
   know what to fix or how". "I need a real RCA and plan".
2. **KISS.** "The current mess we are in is because we have a tendency to over engineer things
   and turn Problems into worse problems with rube goldberg foot guns -- KISS is the law now".
   (RG-0)
3. One cause per task. He asked for a plan of "more like 5-10 tasks" and, shown that two of
   nine each held three unrelated causes, chose one cause per task, with one more task for
   computers: fourteen. The measurement of ruling 4 then made the sync task two, RG-5 to
   measure and RG-6 to build. (RG-1 to RG-15)
4. Sync is chosen by measurement. He chose: fix what blocks both methods first (the join veto,
   the trust change, key delivery), then measure both and choose; nothing is built on sync
   until one passes. This replaces the choice of the replacement recorded in ADR-045 R-15.
   (RG-5, RG-6)
5. The release bar. He chose: the busy-room journey, the restart and update journey, and the
   install journey, on the shipped assets, in VMs; no soak. This replaces ADR-045 R-9, R-12 and
   R-13. (RG-15)
6. Three of his answers of 2026-11-13 are changed: a Linux node gets no TPM-sealed credential
   (RG-11); there is no `vox factory-reset` in this release (RG-10); the 13-journey fleet and
   the designs listed under "Not built" are not built. One is confirmed: removing a computer
   evicts its nodes from rooms (RG-8).
7. "we use ADRs for the documentation": this ADR, not a release plan, is the planning source of
   the v0.4.31 tasks.
8. Acceptance. Shown the draft with its fifteen requirements, without a `vox node compact`
   command or a `vox status --sync` flag, and with the smaller change built if both sync
   methods pass: "yes, get the adr updates landed on main, do the work needed to get
   https://github.com/robertelee78/vox/milestone/35 ready for exexcution with the new tasks,
   then get https://github.com/robertelee78/vox/milestone/35 landed (the new work)".

**Earlier rulings that stand**, because they say what a person gets: no fix without a
reproduced cause, and a reproduction that also appears without its trigger is not evidence
(ADR-045 R-5, R-6); a join is admitted by one member (ledger row 37); a trust change that
cannot finish in one room blocks posting only in that room, and "nothing is sent that the
removed member should not read" (row 35); "people should be able to leave a room that has
already been ended" (2026-11-12); a rejoin is a fresh join (row 34); "one save, one trip" (row
74); every post within 5 seconds, with the 99-of-100 time recorded and no target until it is
measured (rows 80, 81); Session steps are kept two days (row 49); a member that cannot be
connected to reads `offline, last seen <dur> ago` (row 27); no room-repair command (row 22);
claims made on v0.4.30 are kept across the update (row 44); a root with no service manager gets
its daemon back at the next client and says `unsupervised` (rows 46, 47); Vox never writes a
passphrase file on its own (ADR-038 FX-34); a private Session record carries one signature, the
author's (ADR-047 Q2); a store reported corrupt is left untouched (ADR-047 Q5); existing stores
are never reset (ADR-047 Q6); an agent turn that ended with no decision after news was shown
stays uncertain, says so in one sentence, and is never shown again (rows 36, 79); a key
package's sealed body is kept by members only, and an anchor that is not a member stores and
forwards nothing (row 40); all machines move to v0.4.31 together (row 18); an incident with no
reproduced cause ships named as open, and nothing is captured on the decider's Mac (ADR-045
R-11); a verifier runs the release journeys itself (row 52); nothing runs on his machines, and
VMs on this Mac use at most 20 vCPU and 48 GB and stop within 30 s (R-3, R-10, R-11).

## Context: what was reproduced

Status words: **KNOWN** = reproduced on a release binary, or read at the tag, with where;
**INFERRED** = fits the evidence, not reproduced; **UNKNOWN** = not explained. Every recorded
run below had free disk except C-12's.

| # | What the person sees | The rule in the code at v0.4.30 | Recorded |
|---|---|---|---|
| C-1 | Members are connected and nothing arrives | A fetch needs four round trips before its first message. It is discarded one second after it was built if its author has posted again (`actor/bounded_sync.rs:18`, `:4108-4121`) | KNOWN. v0.4.30 asset, relay at 75 ms a hop, author at 2 posts a second: the reader holds 3 of 677 posts; direct on loopback, 542 of 542. v0.4.29 fails alike (`rca-RcaWedge`) |
| C-2 | `cannot join: remote admission may have occurred, but its acceptance could not be verified and saved` | Every connected member must answer the join's seat question within 5 s (`seatstream.rs:48`, `:219-221`) | KNOWN. v0.4.30 asset: a join through a fast member fails in 6.4 s while another member's process is paused 1.5 s in every 3 s; 10 of 12 earlier joiners fail (`arm-repair`) |
| C-3 | Every post on the node is refused `computer trust changed while this command was being applied`; rooms read `trust withdrawal is incomplete` or `authored save worker stopped` | A trust change reserves every open room and walks them in turn. One room's error marks every reserved room failed (`actor/policy_save.rs:172-182`, `:1384-1389`; `channel/pending_text.rs:748-761`); the node is never recorded current; nothing runs the pass again until the next policy event. The pass also needs every room to have no write in flight (`actor/trust_save.rs:628-701`) | KNOWN. v0.4.30 binary, a left room that still holds a removed computer's node: the node stays `applying`, every post is refused, 49 `attention waits for current computer trust` lines (`plan-D`, rig26). The decider's IO machine logged the same pair of messages |
| C-4 | After a daemon restart an agent conversation never gets room news again: `delivery in this conversation is uncertain; start a new native OMP conversation` | After it reads the turn's decision, the hook reads live daemon state again before it finishes (`agent_hook.rs:3596-3601`); a stopping daemon makes it exit 1, and the extension refuses the conversation from then on (`omp-extension.ts:259-265`, `:516-520`) | KNOWN. Published v0.4.30 Mac asset: `vox daemon --restart` during a held turn; hook exit 1, then 78; a later post reaches the node and is never shown (`adr050/f/timeline.log`) |
| C-5 | Status says healthy while a room receives nothing | A round that brought nothing counts as a completed sync (`actor/bounded_sync.rs:4050-4063`); health is computed from rounds and connections | KNOWN. Every surface was green for three hours while a node was cut off (`rca-systemic`) |
| C-6 | A restart causes two outages; sessions print `node … is unavailable` | The restart stops the old daemon, waits, then starts the new one (`update/restart.rs:516-527`); a hook that finds no daemon in that gap starts its own (`daemon_client.rs:123-136`) | KNOWN. A hook started a daemon 0.4 s into the gap and the real replacement restarted it again; five daemon generations in 23 s (`rca-RcaSessions`) |
| C-7 | A prompt typed during an update gets no room news | A client refuses a daemon of another package version though the protocol number matched (`daemonipc.rs:2271-2282`) | KNOWN. 0.4.29 to 0.4.30: `Vox's daemon is 0.4.29 and this vox is 0.4.30` (`rca-RcaSessions`, run b2) |
| C-8 | After a profile was started over, the node's store belongs to the old identity | A store rewrite renames over the path string it was opened with (`store.rs:792-794`, `:876`), so a daemon still running on the old profile writes into the new one; a store is compared with its vault only at unlock | KNOWN on the v0.4.26 binary, and on the decider's Mac (a 2.1 GB store in a new node); not run again on v0.4.30 (`rca-RcaStore`) |
| C-9 | Linux install prints `the installed binary did not run`, and the previous binary is gone | ADR-051's causes: no libc floor in the build; the installer replaces before it runs the candidate (`install.sh:367-381`) | KNOWN (ADR-051) |
| C-10 | A Linux node needs its passphrase after every daemon restart | A typed unlock keeps the secret nowhere a new daemon can read it (`client.rs:866-873`, `keychain.rs:155-182`) | KNOWN (`rca-RcaSessions`, run c1) |
| C-11 | A computer reachable only through an anchor never learns a new node of its group | Computer management keeps only the anchors of the process that started the daemon; an anchor added later reaches the nodes only (`computer/pairing.rs:413`; `host.rs:1064-1073`) | KNOWN. v0.4.30 asset: red; red with `vox anchor add`; green in 3.0 s with the one change of starting the daemon with `--anchor` (`rca-relay-only`) |
| C-12 | After a full disk is freed a node receives nothing, and leaving a room fails | A sync cleanup that failed to save is kept for good and counts against a node-wide limit of 12; at 11 no round starts (`actor/bounded_sync.rs:580`, `:1789-1810`, `:1854-1860`). Leaving a room with such a cleanup fails (`actor/leave_save.rs:1467-1488`) | KNOWN on a 64 MiB image on macOS and on Linux (`rca-RcaSchedStall`; `fleet-exp/receipts/E9a-attempt6-MEASURED`) |
| C-13 | Stores grow to gigabytes | Every Session change rebuilds every Session's rows; a step stores its body twice and two signatures; a small row beside a large value takes a whole page; each abandoned fetch writes proof rows that are never removed | KNOWN, measured (`rca-StoreSize`, `rca-RcaChurn`) |
| C-14 | Status and posts lag while agents step | Session steps and attention commit on the actor and the daemon's two runtime threads; attention reads take the store's writer; every view update walks up to 1,000 unread rows that nothing reads (ADR-044's Context) | KNOWN on an instrumented build. On the v0.4.30 asset with ten sessions: 3 and 2 posts over 5 s of about 5,350; status at most 1.3 s (`perf-baseline`) |

**The busy-room case has never passed on any build.** A busy room, one slow member, a late
joiner: v0.4.30 fails the join (C-2). The repair of today's sync and the replacement prototype
both got past the join and both failed: the newcomer held the slow member's posts within 8 s and
could not read them, because the slow member never applied the newcomer's grant and never sent
its key (`arm-repair`, `arm-replace`). The replacement cut a quiet room's catch-up from 50 s to
about 2.5 s; it does not reach that failure. So the join, the trust change and key delivery come
first, and the sync method is chosen after they are fixed (ruling 4).

**Not explained (UNKNOWN), and not fixed by guess:** whether C-1 is what stopped the decider's
rooms (it needs about 250 ms an answer; that was never measured on his machines); why a key is
still not sent after the grant is applied (fix-list item 100; the 30 s fallback exists at
`actor.rs:16196-16255`); a node's actor blocked 136 to 214 s at the own-history fence (item 89);
the Mac's outage of 2026-11-12 (item 60; clearing backoff on a new connection is already done at
`actor.rs:16881-16912`); the relay wait of 60 s before it fails (item 95); the app's refused
pairing code (item 35); who stopped the Mac's daemon, and why its login item was not running
(item 47); why beast took minutes to reopen its rooms; what made an update report `did not
quit within 30 seconds` (item 46; RG-9 stops judging the quit by a cached flag, which is wrong
whatever the trigger was).

## Terms

- **The busy-room journey**: RG-1's proof.
- **Slow member**: a member made slow outside the product: its serving process paused 1.5 s in
  every 3 s, or its path delayed so that each answer takes 300 ms or more.
- **Red, green, mutant**: as ADR-018. A proof is red on v0.4.30, green on the candidate, and
  red again on its own assertion when the named change is undone.

## Requirements

Each requirement gives the rule, why, the change, and its proof. "Carries" names the tasks of
`docs/release/v0.4.31.md` whose failures it answers; `regroup/ledger.md` has the verdict on each.

- **RG-0. KISS is the law.** A change MUST remove a reproduced cause, and MUST be the smallest
  change that removes it. A registry, protocol, store format, ledger, journal, scheduler or
  framework MUST NOT be added unless a requirement here cannot be met without it, and the task
  that adds it says why. Where a cause is UNKNOWN, the task traces it and changes nothing until
  it is known. One requirement carries one reproduced cause; smaller faults found in the same
  code ride with it. *(Amended 2026-11-23 by ADR-053: for sync and storage, one design fix replaces one cause per task; KISS stands.)*
  - *Why*: ruling 2. The 85 tasks came from 300, from eleven ADRs of 1,400 to 4,000 lines each;
    17 prescribed a fix the evidence does not support, and 8 were diagnostic only, 4 of them
    with no known cause.

- **RG-1. One busy-room journey, with a timeline, decides the room requirements.** One proof
  MUST stage: a room of at least 300 entries, three authors each posting once a second with
  agent Sessions stepping, six earlier late joiners, one slow member, and a newcomer that joins
  through a fast member. It runs on the shipped binary with free disk. For each member it MUST
  record, from what the product itself reports, when the newcomer holds that member's post,
  when the member has applied the newcomer's grant, when the member's key is delivered, and
  when the newcomer shows the post; and the same toward the newcomer. Its verdict is counted in
  posts, never in seconds: red when a member has made 100 posts since the join and the newcomer
  shows none of them, naming the first step of that member's timeline that did not happen;
  green when every member's posts are shown both ways and, after the authors stop, every
  acknowledged post is shown on every member.
  - *Why*: the case has never passed, and three earlier rigs gave wrong answers: a reader that
    never paged (`arm-repair`), a slow member made by a knob build and not the shipped binary
    (fix-list item 83), and a quiet loopback room.
  - *Change*: none in the product. The reader MUST page until it finds the row or reaches the
    room's start; the journey MUST show its slow member was slow; a staging it did not reach is
    APPARATUS.
  - *Proof*: extends `a_newcomer_reads_the_whole_history_proof.rs`. Red on v0.4.30: the join
    fails (C-2). Its own check: a row planted first in a 5,000-row room is found.
  - *Carries*: B03, B77 (the unsent key is traced on this timeline before anything is
    changed).

- **RG-2. A join is admitted by the member it goes through.** A connected member that does not
  answer the seat question MUST NOT fail a join; it learns of the newcomer as an offline member
  does. The room's member cap (ADR-007 G-22) MUST still hold.
  - *Why*: C-2; ledger row 37.
  - *Change*: `seatstream::Asked::Unanswered` no longer fails the join (`seatstream.rs:219-221`;
    `actor.rs:3470-3555`).
  - *Proof*: the busy-room journey reaches its newcomer's join and passes it. A room one below
    its cap, two newcomers joining at once through two members: one is admitted. Mutant: an
    unanswered member fails the join again.
  - *Carries*: B42.

- **RG-3. A trust change applies room by room, and a room that cannot finish blocks only
  itself.** A trust change MUST NOT reserve, wait for or mark any room but the one it is
  working in. The node is current once its keyring is saved. A room whose withdrawal is not
  finished MUST refuse its own posts, saying why, and MUST release no key, until it is finished;
  no other room is refused. A room this node has left owes nothing. An unfinished room MUST be
  finished when it can proceed, with no restart and no new policy event.
  - *Why*: C-3; ledger row 35. The fence is not optional: today the whole node is refused so
    that a removed member reads nothing new; the per-room refusal keeps that for the one room
    that still owes it.
  - *Change*: `release_rooms(.., poison = true)` over every reserved room goes
    (`actor/policy_save.rs:172-182`, `:1384-1389`); the all-room reservation and its
    no-write-in-flight condition go (`actor/trust_save.rs:628-701`); the applied revision is
    stored after the keyring save.
  - *Proof*: extends the trust journey of `nodes_of_one_daemon_proof.rs`. Red on v0.4.30: rig26
    (C-3). Green: with a left room holding a removed computer's node, a new node is created on
    another computer of the group; the node becomes current and another room posts. A room held
    unfinished (a `test-knobs` build): the withdrawn node shows nothing posted there after the
    withdrawal, the poster is told why, and a member that asks that room for a key gets none
    until the withdrawal is finished, then gets it. Mutants: mark every reserved room again;
    let the unfinished room post; let the unfinished room release a key.
  - *Carries*: B19, B20, B21, B22, B24, B80, B81.

- **RG-4. A "not yet" is retried by whoever was told it, and no refusal ends a conversation.**
  At these four places, each KNOWN:
  1. *The agent turn.* Once the turn's decision is read, the hook MUST save it and finish from
     what it already read. A refusal or a stopped daemon after that MUST NOT make the
     conversation uncertain: the next hook finishes it (`agent_hook.rs:3596-3601`;
     `omp-extension.ts:259-265`). A turn with no decision is unchanged (rows 36, 79).
  2. *Session registration.* A write that finds the registration lock held MUST wait for it; a
     rename or a room move is acknowledged only once saved (`wake.rs:769-815`, `:930-955`).
  3. *A sibling node starting.* The daemon-wide gate MUST be held only while policy is
     installed, not through the reopening of rooms, and a Session opening refused by it MUST be
     tried again when it frees (`actor/startup_save.rs:420-459`, `:601-630`; `host.rs:2176-2212`).
  4. *The key request.* The refusal `room governance is refreshing` MUST be one typed refusal
     that the retry recognises, and an abandoned attempt MUST be cleared
     (`channel/history/read_resource.rs:91-102`; `channel/key_package_queue.rs:644-646`).
  Two faults in the same hook code ride with this task: a session in a linked worktree MUST be
  offered its repository's room (`room_map.rs:309-339`), and the `vox agent room --none` refusal
  MUST say who may change the room map (`agent_room.rs:127-138`).
  - *Why*: C-4; fix-list items 28, 29, 30, 31, 65, 97, 99.
  - *Proof*: the journey that drives the real OMP extension. Red on v0.4.30: run f (C-4).
    Green: a daemon restart during a held turn, then a post: it is shown, once. Nine sessions
    restarted together print no `session registration is busy`. Mutants: one per place.
  - *Carries*: B08, B09, B10, B23, B37, B67, B68, B76, B85.

- **RG-5. The sync method is chosen by measurement.** After RG-2, RG-3 and RG-4 land, the
  busy-room journey MUST be run on two builds: today's method with two rules changed (a fetch
  in flight is never discarded because its author posted again; each peer has its own turn),
  and the replacement prototype (branch `proto/range-sync`). No sync change lands in the
  product before that. If one passes, it is built. If both pass, the smaller change is built
  (RG-0). If neither passes, nothing is built on sync: the first step the timeline shows
  missing is the next cause, and the decider is told. *(Superseded 2026-11-23 by ADR-053: neither passed; the sync is built by ADR-053's Order.)*
  - *Why*: ruling 4. Both methods failed for causes outside sync.
  - *Proof*: the two verdict lines of RG-1's journey, with each build's commit.
  - *Carries*: B38.

- **RG-6. Sync makes progress.** With the method RG-5 chose: a message a member holds is shown;
  a missing body is asked for until it arrives; a slow peer delays only itself; a newcomer
  reads the room's recent messages at once and older ones when a person pages back, and is
  never made to read from message one (the decider, 2026-11-13, ledger row 63). Whichever
  method is built, a key package's sealed body is kept and served by members only (row 40).
  - *Why*: C-1; fix-list items 1, 2, 4, 7, 10, 12.
  - *Proof*: the busy-room journey green on the candidate. The relay act of
    `key_package_proof.rs` at 75 ms a hop: red on v0.4.30 (3 of 677), green when both sides
    show every post. A reader 8,000 entries behind catches up. A node that left and rejoined
    posts at once. Mutant: discard a fetch when its author posts again.
  - *Carries*: B39, B40, B41, B43, B45.

- **RG-7. Status, words and the log say what happened.**
  1. A round that brought nothing MUST NOT count as a sync, and a message counts as held only
     when it can be shown (`actor/bounded_sync.rs:4050-4063`).
  2. Each room's line in `vox status` MUST say what it rests on: through which message it has
     received each member. A room where a connected member has posted 20 messages this node
     does not hold reads `not receiving`. The app's room row shows the same verdict.
  3. No message blames trust, the passphrase or a worker for a sync or disk cause: `authored
     save worker stopped`, `a join did not complete` for a settlement, `has not trusted you`
     before trust has arrived, and `usually the room passphrase is wrong` for a member's disk
     are replaced (fix-list items 24, 50, 52). A member whose daemon answers and whose node is
     not attached reads `not attached`, not unreachable (item 56).
  4. The daemon log MUST keep 24 MiB (row 25), MUST NOT be cut at open
     (`daemon_log.rs:44-47`), and a repeated line records when it last happened.
  5. A desktop notification that blocks MUST NOT hold up the next notice; a machine with no
     notification service logs that once (`notify.rs:134-159`).
  - *Why*: C-5; without it the next failure is again found by reading code.
  - *Proof*: extends `vox_status_shows_the_node_proof.rs`: a member that advertises posts and
    serves none. Red on v0.4.30: `last sync 0s ago`. Mutant: count an empty round.
  - *Carries*: B25, B26, B27, B28, B47, B48, B49, B50, B51.

- **RG-8. Computers.**
  1. Computer management MUST use the machine's current anchors, as its nodes do, without a
     restart (ADR-043 CJ-17, built as written).
  2. Pairing with no address to reach MUST say so at once, and whoever holds a half-made
     pairing can close it at once (fix-list items 33, 75).
  3. `vox computer status` MUST open with where this computer stands and what to run next
     (item 34).
  4. `vox computer remove` MUST ask once, MUST never offer the removed computer's nodes for
     trust again, and MUST evict them from the rooms this computer administers through the
     existing `vox room remove-member` (ADR-007 G-28), unless `--keep-rooms`. The choice is
     saved with the removal before any eviction; evictions resume after a restart; a member
     already gone is done; an eviction a room cannot take yet is tried again when the room
     next opens; where no local node may evict, status names the room, the node and the
     command. ADR-043 CJ-11 and CJ-12 hold the cases; where they wait on ADR-040's registry,
     this text binds (the decider, 2026-11-13 and 2026-11-20).
  5. A refused `vox room pause` MUST name the node that can pause and the command (item 37).
  6. The app's refused pairing code (item 35) and the invite that does not answer at once
     (B61) are UNKNOWN: each is traced before any change.
  - *Why*: C-11; ruling 3.
  - *Proof*: extends the pairing journey of `nodes_of_one_daemon_proof.rs`. Red on v0.4.30: the
    relay-only run with `vox anchor add` (C-11). Mutant: drop the delivery of anchors to
    computer management. Removal: after `vox computer remove` and a daemon restart, the
    computer's nodes are in no room this computer administers and are not offered.
  - *Carries*: B61, B62, B63, B64, B65, B66, B84.

- **RG-9. A restart is finished by something that outlives its caller.** The replacement daemon
  MUST be started before the old one is stopped, and a client that finds no daemon while a
  restart is in progress MUST wait for it, not start one. A daemon stopped by a signal it did
  not ask for is brought back by the login item or user unit where one is enrolled, and by the
  next client where none is (rows 46, 47). A daemon stop logs who asked, the trace item 47
  lacked. `vox update` on a Mac keeps the old daemon serving until the bundle is swapped, and
  judges the app quit by its process, not by a cached flag.
  - *Why*: C-6; fix-list items 41, 46, 47, 81.
  - *Change*: `update/restart.rs:516-527`; `daemon_client.rs:123-136`;
    `update/bundle.rs:1129-1181`, `:3925-4008`.
  - *Proof*: extends `the_daemon_and_its_nodes_proof.rs`. Red on v0.4.30: a prompt typed during
    a restart starts a second daemon. Green: one daemon generation, the prompt's turn gets its
    news, and a restart whose caller is killed still leaves a daemon serving. Mutant: stop,
    then start.
  - *Carries*: B05, B06, B12, B17, B78.

- **RG-10. A version change or a rebuilt profile never crosses identities or drops claims.**
  1. A client MUST work with a daemon of another package version when their protocol numbers
     match (`daemonipc.rs:2277-2282`; `omp_watch.rs:92-116`); `vox update` still checks the
     version it installed.
  2. Claims MUST be compared by a claim-rules number that changes only when the claim rules
     do, not by the package version string, and claims made on v0.4.30 are kept
     (`coord.rs:878-881`; `vox-agentcomms/src/version.rs:123-130`). The control-protocol number
     is the client's contract with its daemon, not the room's, so it does not serve.
  3. A daemon MUST write only into the profile directory it opened, never to whatever a path
     string names after that directory was replaced: the store rewrite, pause locks,
     decisions, files and pulls alike (`store.rs:792-794`, `:876`; `rca-RcaStore`). A store
     MUST be compared with its vault before any write (`profile.rs:269-318`).
  4. A conversation registered as one identity MUST NOT act as another: after its node is
     rebuilt under the same name it is refused in plain words (`omp_fence.rs:218-281`).
  5. A daemon restart prints one `reconnecting` line in a conversation, not `node … is
     unavailable … vox node create` (`omp_watch.rs:273-274`).
  6. A conversation whose OMP process has exited is ended once and removed (fix-list item 42).
     How Vox knows the process exited is traced first: a stopped watcher is not proof.
  - *Why*: C-7, C-8; fix-list items 40, 42, 43, 44, 45, 48.
  - *Proof*: extends `update_proof.rs` and `the_daemon_and_its_nodes_proof.rs`. Red on v0.4.30:
    run b2 (C-7); a profile directory replaced under a running daemon whose leave then
    completes (C-8). Mutant: one per rule.
  - *Not built*: `vox factory-reset` and `vox agent session rebind`.
  - *Carries*: B07, B13, B14, B15, B16, B79.

- **RG-11. Linux installs, and stays unlocked across a daemon restart.** ADR-051 is built as
  accepted, its proofs running as RG-15's install journey. A Linux node unlocked by a typed
  passphrase MUST come back Ready after a daemon restart, update or crash with nothing typed,
  its secret held in the kernel keyring. After a reboot it comes back from a passphrase file
  the person chose, or says `Locked` with the command to unlock. The installer writes
  `/etc/sysctl.d/90-vox.conf` when run as root and otherwise prints the commands (ADR-044 Q3).
  - *Why*: C-9, C-10; fix-list items 19, 39, 91.
  - *Proof*: `install_sh_proof.rs` and `update_proof.rs` as ADR-051 LB-6; a Linux node, a
    daemon restart, `vox status` reads Ready. Mutant: do not store the secret.
  - *Carries*: B02, B54, B69, B70, B71.

- **RG-12. No store commit runs on the actor.** Session steps and attention commit off the
  actor and off the daemon's two runtime threads; attention reads take no writer; the view no
  longer walks unread rows nothing reads; a restarted room's refresh walks only its own Session
  records and schedules its next batch itself. With ten agent sessions stepping, `vox status`
  answers within 1 s and every post returns within 5 s.
  - *Why*: C-14; fix-list items 15, 16, 18, 68; rows 74, 80, 81.
  - *Change*: `actor.rs:8740-8788`, `:23306-23351`; `channel/attention.rs:173-175`, `:206-208`,
    `:382-393`, `:597-600`; `channel.rs:8833-8861`; `channel/pending_session.rs:1402-1494`.
  - *Proof*: extends `a_post_answers_promptly_while_a_peer_posts_proof.rs` and
    `a_daemon_reopens_its_rooms_proof.rs`. Red on v0.4.30 (`test-knobs`): status does not answer
    within 1 s while a flush is held with a step in flight. Mutant: commit the step on the
    actor.
  - *Carries*: B11, B18, B52, B53.

- **RG-13. A store grows with what it holds.** A change to one Session MUST rewrite only that
  Session; a Session step stores its body once and one signature; a small row MUST NOT take a
  whole page; fetching writes no proof rows (an in-memory cache of at most 8 MiB, ADR-044 Q2);
  Session steps are kept two days by default, not seven, and an admin's own setting holds (row
  49); a store with more than twice the space it uses is compacted at daemon start; `vox
  status` shows each store's size and the free disk. Existing stores keep working and are
  converted in place only where one of these changes needs it. *(Amended 2026-11-23 by ADR-053: "fetching writes no proof rows" is narrowed by MP-7; compaction at daemon start is replaced by MP-15; per-message residue by MP-14 and MP-16.)*
  - *Why*: C-13; fix-list items 20, 22, 25, 76 to 80.
  - *Proof*: extends `retention_proof.rs`. Red on v0.4.30: the pages written for one step grow
    with the number of other Sessions in the room (100 against 1,500), and a new room keeps
    steps seven days. Green: with a `test-knobs` clock step, a step older than two days is
    gone and an admin's own setting holds. Mutant: rebuild every Session.
  - *Carries*: B44, B55, B56, B57, B58, B60, B82.

- **RG-14. A full disk recovers, and leaving always works.** A sync cleanup that failed to save
  MUST NOT count against any other room, is tried again when its room can save, and is dropped
  when its room is gone. A store recovers in place when writes succeed again, leaves no
  `.failed` copy, and says the disk is full. `vox room leave` MUST succeed at once in every
  state, an ended room included; an ended room is deleted. A left room's hidden copy is kept
  two days, not seven (row 58). A store that cannot be read is left exactly as it is.
  - *Why*: C-12; fix-list items 21, 23, 27, 64, 85, 86, 94.
  - *Change*: `actor/bounded_sync.rs:1789-1810`, `:1854-1860`; `store.rs:658-711`, `:767-914`;
    `actor/leave_save.rs:1338-1354`, `:1467-1488`, `:1555-1577`.
  - *Proof*: extends `a_sync_failure_names_its_reason_proof.rs` and
    `a_room_can_be_left_and_ended_proof.rs`. Red on v0.4.30: two fill-and-free cycles on a
    64 MiB image, then nothing is received and a leave fails (C-12). Mutant: count failed
    cleanups again.
  - *Carries*: B29, B30, B31, B33, B34, B35, B36, B46, B83.

- **RG-15. The release bar.** v0.4.31 is released only when three journeys are green once, on
  the assets that ship, in VMs on this Mac: the busy-room journey (RG-1); the restart and
  update journey (RG-9, RG-10, with RG-4's agent turn); the install journey (RG-11). A
  verifier that wrote none of the changes runs them itself; the author's receipts are not its
  evidence (row 52). There is no soak and no fleet. CI stays compile-only. The release notes
  name every UNKNOWN above as open.
  - *Why*: ruling 5; ADR-018.
  - *Carries*: B01, B04, B32, B73, B74, B75.

## Order

RG-1 first. RG-2, RG-3 and RG-4 are accepted on it and do not wait for each other. RG-5 needs
all three; RG-6 needs RG-5. RG-8 needs RG-3. RG-7 and RG-9 to RG-14 wait for nothing. RG-15 is
last.

## What this ADR supersedes and amends

- **ADR-040, 041, 042, 044, 045, 046, 047, 048, 049 and 050** are superseded for v0.4.31. They
  stand as the record of the failures found and the designs considered. A requirement of theirs
  binds only where this ADR names it; a task MAY take a design from them where RG-0 allows.
- **ADR-043** is superseded for v0.4.31 except CJ-11, CJ-12 and CJ-17, which RG-8 builds; where
  CJ-12 waits on ADR-040's registry, RG-8's text binds.
- **ADR-051** stays accepted. Its proofs run as RG-15's install journey, not as ADR-045's J7
  and J11.
- **`docs/release/v0.4.31.md`** is superseded as the build plan. Its tasks B58, B59, B72 and
  every task's prescribed fix are not built as written; `regroup/ledger.md` says where each
  failure went.
- **ADR-045 R-9, R-12, R-13 and R-15** are replaced by rulings 4 and 5. ADR-045's amendments of
  ADR-018 §10.2 and §10.9 fall with it, except that a verifier runs RG-15's journeys itself.
- **AGENTS.md**, "Releases": the KISS rule is added, in the decider's words.

## Not built

Each was a design of ADR-040 to ADR-050. None is built unless a requirement here turns out not
to be meetable without it (RG-0):

- the per-node registry of waiting work, the two-lane scheduler, and the status `waiting` block;
- the reserve that refuses saves before the disk is full;
- the departure carry records and withdrawal journals for leaving a room;
- the full agent-turn journal;
- the 13-journey fleet, its build stages and the soak;
- the replacement sync and its creator summary, unless RG-5 chooses it;
- the TPM-sealed Linux credential, `vox factory-reset`, and `vox agent session rebind`;
- a `vox node compact` command, and moving the sync counters to `vox status --sync`;
- a first-start conversion of every store.

## Consequences

- Fifteen requirements replace 85 tasks. Each names its cause, its smallest change and its red.
- The busy-room journey is the one place the room requirements are judged, so a fix that moves
  the failure one step along is seen as that.
- The sync decision waits for RG-2 to RG-4 and one measurement. If today's method passes, the
  replacement is never built.
- The release is judged on three journeys. What the fleet and the soak would have caught under
  faults nobody staged is not caught; the UNKNOWN list says what is open.
- Removal with eviction (RG-8) is the one new behaviour in a stabilization release.

## Links

- ADR-007 (G-22, G-28), ADR-018, ADR-043 (CJ-11, CJ-12, CJ-17), ADR-051.
- `docs/release/v0.4.31.md` (the 85 tasks; its Coverage A maps fix-list items 1 to 100 to
  them).
- In the release's evidence archive, outside this repository: `regroup/report.md`,
  `regroup/ledger.md`, `regroup/components/`, `regroup/rulings-2026-11-20.md`;
  `v0431-fix-list.md` (items 1 to 94); `rca-systemic.md`, `rca-RcaWedge.md`,
  `rca-RcaSessions.md`, `rca-RcaStore.md`, `rca-RcaSchedStall.md`,
  `rca-StoreSize.md`, `rca-RcaChurn.md`, `rca-relay-only.md`, `plan-D.md`, `arm-repair.md`,
  `arm-replace.md`; `adr050/f/`; `perf-baseline/REPORT.md`;
  `fleet-exp/receipts/E9a-attempt6-MEASURED/`.
