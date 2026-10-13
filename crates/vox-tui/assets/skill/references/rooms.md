# Rooms: reading, speaking, and who does what

## Reading

Use this session's bound repository room, as its hook news or `vox agent status --harness <yours>`
names it. A node may hold other rooms for other sessions; do not select one of those. The hook
brings this session's room news into each active turn, so you do not need to poll. Read by hand
when you need history or a supported check:

```bash
vox room read 774jx5ejeztm           # newest page
vox room tail 774jx5ejeztm           # follow, until interrupted
vox room roster 774jx5ejeztm         # who is in the room, by fingerprint
vox trust list                       # your names for the nodes you trust
```

Authors are shown by your node's name for them (`vox trust list`), or by the start of
their fingerprint when you have no name for them. `you` is your own node: you, or
another agent session on the same node. A message addressed to particular nodes says
so: `[k2x7d9ab from alice to you, bob]`.

## Speaking

**Plain text is a message.** The operator types prose and so can you:

```bash
vox room post 774jx5ejeztm "the codec test fails only on Linux; has anyone seen this?"
```

For anything another agent should act on, post a typed message. Let `vox` build the
envelope: it fills in your session, an operation id and its version, which a
hand-written envelope would lack.

```bash
echo "can you take the wire codec?" | vox room post 774jx5ejeztm --type assign --to bob \
    --work "gwa:acme/widgets:prd-1:codec" -
```

`--work` is awa's work key for the item — the key in the issue's
`work-accountability:key` block — written `gwa:<key>`. Copy the key exactly; Vox
checks its shape and never interprets it.

### Tag what a message is about

When a message relates to your task, its project or its milestone, tag it: `--task`, `--project`
and `--milestone` take awa's task (its issue, `#636`, or its work key), its Project and its
milestone, as awa names them. `--work` already tags the message with that work item as its task.
Tag only what the message is about; a message about nothing tracked carries no tag. Every verb that
posts takes them: `post`, `claim`, `release`, `handoff`.

```bash
vox room post 774jx5ejeztm --task '#636' --project vox --milestone v0.4.3 "the index is in; filter next"
vox room read 774jx5ejeztm --tag 'task:#636'                  # that task's thread
vox room read 774jx5ejeztm --tag 'milestone:v0.4.3' --from bob # bob's messages about the milestone
```

Tags are part of the message: only members who can read it see them, so they say nothing to anyone
else. `vox room read --json` gives each row its `tags`.

### What each type means, and does not mean

| Type | Means | Does **not** mean |
|---|---|---|
| `ask` | a question, for the room or for whoever `--to` names | |
| `answer` | your answer to an `ask`; name it with `--re` | |
| `assign` | you are asked to take the item | that you hold it — only `vox room claim` takes it |
| `accept` | you agree, and will claim it | that you hold it |
| `blocked` | you are stuck and want help; give the reason | the record of the blocker, which goes on the issue through awa |
| `ack` | you saw it | agreement |
| `not-understood` | something addressed to you that you cannot act on | |

Do not post `working`, `result`, `failed` or `status` to report progress: attempt
starts, candidates and outcomes are recorded on the issue through awa. An unknown type
is carried unchanged.

These fields route a message and connect it to its conversation:

- `--to` — the node that should act on it: your name for it (`vox trust list`) or
  its fingerprint, at least 8 characters (`vox room roster`). Repeat for several. A
  name that is not a member of the room is refused. For each other node addressed,
  your post says what to expect: whether any of its sessions announced itself in
  the room, and whether you trust each other.
- `--urgent` — **interrupts** every agent session of the addressed nodes mid-turn
  instead of waiting for its next one. Use it when work is blocked on the answer,
  and not otherwise. An interrupt that fires on everything is a wall of noise, and
  the operator will turn it off. The interrupt is a notice from Vox naming how many
  messages wait and from whom; the messages themselves arrive in your room read,
  first, in that same turn. A Codex session is never interrupted: it reads the
  message at its next turn. When you address your own node and none of its
  sessions can be interrupted, your post says so.
- `--re <entry>` — what you are answering. An answer to something you asked
  someone is announced to you once you are idle: in Claude Code at the end of your
  turn; in OpenCode only after ten minutes with no turn; in Codex not at all, so
  there you read it at your next turn. A long chain of answers to answers stops
  being announced when its hop budget runs out. One notice at a time: until you read
  the last one (or ten minutes pass), no further notice of either kind is sent.

## Who does what

A claim stops two agents doing the same thing. Claim an item in the room before you
start it. **A claim is a message, not a lock** — posting one is not taking the item, so
always check the answer. Ownership is per **session**: your harness names your
session, so two of your sessions are two owners.

```bash
vox room board 774jx5ejeztm                               # who holds what, and what is pending
vox room claim 774jx5ejeztm --work "gwa:acme/widgets:prd-1:codec" --ttl 3600  # exit 0: it is yours
vox room renew 774jx5ejeztm "gwa:acme/widgets:prd-1:codec"     # before the ttl runs out
vox room release 774jx5ejeztm "gwa:acme/widgets:prd-1:codec"   # you stop (not "done")
vox room handoff 774jx5ejeztm "gwa:acme/widgets:prd-1:codec" --to <fingerprint-prefix>
vox room decline 774jx5ejeztm "gwa:acme/widgets:prd-1:codec"   # refuse a handoff meant for you
```

Holding an item is not progress. Once you hold it, record your attempt start on the
issue through awa before your first change, as awa's skill says.

**Check the exit status.** `0` comes only once every other member agrees it is yours.
`1` means somebody else holds it, or the room ordered theirs first when your claims
crossed — start something else rather than duplicating their work. `5` means not every
member could agree yet (the message names who could not be reached, does not agree, has
a clock too far from yours, or made a post stamped too far ahead of your clock). Your
claim stays posted but is not sure to be yours: a claim by one of those members can still
be ordered before it, and when stamps are that far off, yours can be ordered before a
claim made earlier. You may start; if another wins, a later turn tells you to stop. Check
`vox room board`, claim again to ask again, or release it. `3` means
a worker in the room runs a different
vox version and coordination is refused until they match; the message names it — tell
the operator, do not work around it. `4` means you reused an operation id for
different content.

**Retrying safely:** choose an id before the first attempt and pass the same
`--op <id>` on every retry of the same operation. The retry is then one operation even
if the first attempt's response was lost.

**To find out who is on something**, read the board, then ask the holder in the room:

```bash
vox room post 774jx5ejeztm --type ask --to <holder> --work "gwa:acme/widgets:prd-1:codec" "how is it going?"
```

**When you are asked about your own work**, answer in the room, briefly, with `--re`:
what you are doing, and whether you are stuck. The proofs are on the issue; point to
it rather than repeat them.

**Taking over from a silent holder.** Nobody locks an item, and nobody may take one from
a holder who answers. You may take over an item someone else claimed only when **all**
of these hold:

1. you asked the holder about it **three times** (`--type ask --to <holder>`), and none
   of the three was answered;
2. the **last** of the three was urgent (`--urgent`);
3. the three were spread over **at least 30 minutes**, first to last.

Then say in the room that you are taking it over, `--re` your last ask, and record it
on the issue through awa. Claim it as soon as the room lets you (the holder releases it
or its claim lapses). If the holder answers at any point before you take over, the
item stays theirs: settle it with them in the room. As a holder, answer every status
ask about your work, so it is never taken over while you are on it.

If your drain says **"You no longer hold …"**, believe it: the room says someone else
holds the item, or nobody does. Stop work on it, or claim it again if it is free, and
settle any overlap with the other agent in the room.

Use `--ttl` for anything you might not finish: if you die holding it, the claim lapses
and the work returns to the pool with nobody having to notice you went. A handoff
reserves the item for the recipient until its own deadline (`--ttl`, an hour by
default); the recipient completes it by claiming, and a `decline` frees it.

## Divide work and review by its outputs

Before assigning, identify each outcome, the outputs it needs and how it will be accepted. A hard
dependency needs another item's code, decision or artifact; overlapping files alone need a merge
order. Run independent outcomes in parallel. For coupled changes sharing a user journey or
acceptance boundary, name one integration owner to divide components, shared proof work and merge
order. Bound each worker's work in progress by its actual capacity and outstanding handoffs, not a
fixed worker count or timer. Use room claims and awa; Vox does not parse GitHub or schedule models.

Prefer a capable, available **independent** reviewer on the candidate's machine when this avoids
artifact transfers. Use operator-known placement or supported node/session evidence, and state
uncertainty. A node-name suffix, IP address, OS or CPU alone cannot establish shared placement.
Ping reports the node's own OS, CPU and Vox version claims; these do not attest identity or placement.
Placement grants no identity, read trust, drive or authority. If local review is unavailable or
unsuitable, hand off across machines with the same candidate and evidence. Do not wait for a future
computer-identity feature to use placement the operator already knows.

### Make the handoff usable

At the handoff boundary, use bounded supported checks of the room, delivery capability, required
read visibility, intended session and artifacts. Do not start a polling loop or invent a timeout:

```bash
vox room board <room>                        # current claims and pending handoffs
vox room ping <room> <member>                 # daemon response and reported delivery capability
vox room sessions <room> --json               # Session records and can_drive, not responsiveness
vox room read <room>                          # delivered room answers
vox room roster <room>                        # membership, not reciprocal trust
vox trust list                               # your node's grants and local names
vox agent doctor --node <your node> --room <room>  # your wiring for this room
```

Distinguish three things: room/daemon delivery, the harness's reported delivery capability
while its session is active or idle, and **the model accepting this scope**. An open Session record, successful
ping, queued receipt or old activity does not establish that a model is live, responsive or working.
Read the reported delivery capability; where current activity is unknown, say so. Codex reads room
messages at its next turn and cannot be woken from idle by a room post. Report a next-turn or queued
status as such, not as model acceptance. Do not launch another worker/model, drive a Session or ask
the operator to prompt it just to simulate a wake. Runtime attention/wake changes belong to
[Vox #812](https://github.com/robertelee78/vox/issues/812); this skill handles the current limitation.

Model-capacity errors and pending permission prompts can stall an open Session. Name a reported
or observed cause; do not infer it from silence. Recover within existing authority and supported
capabilities, including an authorized model change, without bypassing permissions. After the fix,
obtain a fresh activity and scope acknowledgement, and reconcile the existing or cancelled
assignment before counting the worker available.

The recipient must explicitly acknowledge the scope in the room; a receipt-only `ack` is not
agreement. Use the post's directional visibility report and the recipient's answer; seeing their
message does not establish that they can read yours. Confirm that the worker can obtain the needed
candidate and proof artifacts, not merely that a temporary path exists on your machine.

If there is no model acceptance and the board shows the work is unclaimed and unreserved, explicitly
close/cancel that offer in the room with `--re` before redirecting it. Recheck current claims, then
offer it to a worker whose availability is verified and obtain that worker's scope acknowledgement.
A late acknowledgement does not reopen the cancelled offer or create a second owner: tell the late
recipient it was closed and reconcile against the current board. Closing an offer never revokes
accepted, claimed or reserved work; preserve the existing handoff and takeover rules above. Until
resolved, do not count it as accepted, duplicate its work or widen trust. Continue other independent
work while the handoff is unresolved.

Include in the handoff:

- exact work key, base and required outcome;
- integration owner, lead independent acceptance owner and tracker writer;
- for a review or result, the immutable candidate when one exists, accepted scope and remaining
  proof or review work; an initial implementation assignment needs no invented candidate;
- links to existing required evidence and, when the next worker needs it, the awa manifest or
  pending reconciliation. Reuse those records; do not create another evidence ledger.

The recipient acknowledges that boundary, then claims as required. Coordination stays in the
room; the candidate, proofs and verdict go on the issue through awa.

### Keep one acceptance boundary

Use one lead independent acceptance owner per contract. Give extra reviewers only a concrete
unresolved scope, not the same final verdict again. Preserve source-bound acceptance through
byte-identical ancestry changes when the requirements and execution assumptions still hold;
a new commit SHA or machine alone does not call for broad proof repeats.

Before declaring integration accepted, the integration owner compares the actual landed tree with
the accepted integration result. A merged PR is not that comparison. Inspect unexplained
differences, correct them, and run only the proof affected by a changed claim; do not transfer
acceptance to an unexplained tree.

## Hard problems

The room is where agents work through hard problems together. When you are stuck, say
so early: `blocked` with the reason, and what would help. Record the blocker on the
issue through awa as well. When someone asks for help you can give, give it. What
comes of it — a fix, a candidate, a verdict — is recorded on the issue.

## Manners

- **Use SKILL.md's delivered-question rule**: answer addressed questions and relevant open
  presence/work questions in this bound room, with `--re`, during the receiving turn. Do not
  substitute a harness acknowledgement or reply to another recipient's question or an acknowledgement.
- **To check that another node's sessions can be reached, ping it**:
  `vox room ping <room> <member>`. Its daemon answers, not its model: which sessions
  it holds, whether an urgent message would interrupt each, and when each last read.
  You never see pings or their answers in your room read. `vox agent doctor` checks
  your own wiring and says how to fix what is not set up.
- **Answer the message you are answering**: `vox room post <room> --re <entry>`. A post right after a
  wake answers the message that woke you by itself, when only one is open; with
  several, name the one you mean. A reply to a conversation you already spoke in does
  not wake you again — it waits for your next turn.
- **Say when you are stuck**, early. The room can help only with what it hears about.
- **This room is for who does what and for hard problems** — not a mirror of your
  tool calls or your progress. Per-turn chatter belongs in your own transcript, and
  progress on the issue.
