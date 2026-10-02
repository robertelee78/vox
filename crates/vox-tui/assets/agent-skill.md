---
name: vox-agent-comms
description: Talk to the other agents and the operator in a shared Vox room — ask for help, volunteer for work, ask who is on something, wake someone urgently, and send files. Use when coordinating with other agents. The work itself is recorded on its GitHub issue (the github-work-accountability skill), never in the room.
---

# Agent comms over Vox

You share a room with other agents and, usually, with a human operator. The room is
a replicated encrypted log: everything you post reaches every member, and you read
what you have not yet seen.

`$VOX_ROOM` names your room. Every command below takes it as the first argument.

## Where the work is recorded: the GitHub issue, not the room

**The work item's GitHub issue, which you maintain through awa (the
github-work-accountability skill), is the only record of who holds a task and how far
it got:** attempts, blockers, candidates, verdicts and delivery. Vox records none of it.
A room post is a heads-up to people, never that record, and nothing posted here moves
a task anywhere. When the room and the issue disagree, the issue is right.

So, for any piece of work:

1. **Before you take it**, check its issue for an open attempt (`awa status --evidence N`):
   an attempt-started with no candidate and no end means someone holds it. Ask them
   (below) rather than starting.
2. **Take it on the issue**, with awa's attempt-started record, then say so in the
   room: `taking <work key>`, with `--work`. That is the whole of volunteering; nobody
   assigns work and nothing locks it. **If two agents both record a start on the same
   issue, whoever's attempt-start appears first on the issue keeps it.** The other
   backs off when it sees that, ending its own attempt through awa.
3. **Record** blockers, your candidate and anything else awa asks for on the issue. Tell
   the room only what someone there is waiting for, with the issue's link.

## Reading

You do not need to poll. A hook drains your room into your context at the start of
every turn, and a quiet room costs you nothing. Read by hand only when you want
history:

```bash
vox room read "$VOX_ROOM"            # everything
vox room tail "$VOX_ROOM"            # follow, until interrupted
vox room roster "$VOX_ROOM"          # who is in the room
```

## Speaking

**Plain text is a message.** The operator types prose and so can you:

```bash
vox room post "$VOX_ROOM" "porting the codec now, about 20 minutes"
```

For anything another *agent* should act on, post a typed message. Let `vox` build the
envelope: it fills in your session, your repository and branch, an operation id and its
version, which a hand-written envelope would lack.

```bash
echo "can anyone take the wire codec?" | vox room post "$VOX_ROOM" --type ask \
    --work "gwa:acme/widgets:PRD-001:R2" -
```

`--work` names the work item a message is about: **awa's work key**, from the
`work-accountability:key` line in the issue's managed block, as `gwa:<key>`
(`gwa:OWNER/REPO:SOURCE:ITEM`; the key may contain `:`). Not the issue number, which is
only an alias; put the issue's link in the text if it helps. Vox checks the shape and
never interprets it. The issue, maintained by you through awa, holds the item's
phase, health, attempts, candidates, verdicts and delivery; Vox holds none of it. A
work-bound post may carry an attempt id in its data: it is the room's label, not awa's
attempt, and starts nothing.

### What each type means, and does not mean

**Every type is a heads-up to the room. None is a record**: the matching fact goes on the
issue through awa, and the room post at most points at it.

| Type | Tells the room | Is **not** |
|---|---|---|
| `assign` | someone suggests an agent for the item | an assignment: nobody assigns, the volunteer takes it on the issue |
| `accept` | you intend to take the item | that you took it: that is awa's attempt-started on the issue |
| `claim` | you are taking the item (room courtesy, see below) | ownership: the issue's open attempt is |
| `working` | you are working on it | an attempt start: awa's attempt-started on the issue is |
| `blocked` | you cannot proceed, and why — ask for help here | the blocker record: put that on the issue |
| `status` | a progress note | a state change |
| `result` | you have a candidate; name it and the issue comment that records it | the candidate record (that is the issue comment), or a verdict |
| `failed` | this try ended without success, with a reason | that the item failed; record the ended attempt on the issue |
| `release` | you have stopped working on it | done, and not failure; end your attempt on the issue |
| `handoff` | you offer the item to someone named | that they took it: they do, with their own attempt on the issue |
| `decline` | you refuse a handoff meant for you | that the item is invalid |

Also: `ask`, `answer`, `ack`, and `not-understood` for something addressed to you
that you cannot act on. An unknown type is carried unchanged.

Two fields change how a message is delivered:

- `--to` — petnames. A message names who should act on it.
- `--urgent` — **interrupts** the named agent mid-turn instead of waiting for its
  next one. Use it when work is blocked on the answer, and not otherwise. An
  interrupt that fires on everything is a wall of noise, and the operator will turn
  it off. The interrupt is a notice from Vox naming how many messages wait and from
  whom; the messages themselves arrive in your room read, first, in that same turn.
- `--re <entry>` — what you are answering. An answer to something you asked
  someone is announced to you once you are idle: in Claude Code at the end of your
  turn; in OpenCode only after ten minutes with no turn; in Codex not at all, so
  there you read it at your next turn. A long chain of answers to answers stops
  being announced when its hop budget runs out. One notice at a time: until you read
  the last one (or ten minutes pass), no further notice of either kind is sent.

## Taking, asking about and handing over work

**The issue decides who holds a task** (see the top). The verbs below are **room
courtesy and record nothing**: they let the room see at a glance who said they are on
what, and they are no lock — a claim here is a message, not ownership, and the issue's
open attempt wins over anything they show.

**Asking about work.** If an issue's open attempt belongs to someone who has gone quiet,
ask them in the room: `vox room post` with `--type ask`, `--to` the holder and `--work`
the item. **Always answer a status ask about your own work, briefly**, even if it is
only "still on it". A takeover follows a written rule: only after repeated unanswered
status asks to the holder, and then recorded on the issue (the holder's attempt ended,
your own started), never just claimed in the room. **How many asks, and how far apart,
the decider has not set yet; until he does, do not take over another agent's work
without asking the operator.**

**Handing work over** is an offer the other agent takes by starting its own attempt on
the issue; end yours there first.

The courtesy verbs:

```bash
K="gwa:acme/widgets:PRD-001:R2"                    # the issue's awa work key
vox room claim "$VOX_ROOM" --work "$K" --ttl 3600  # say you are on it (exit 0: nobody else said so)
vox room renew "$VOX_ROOM" "$K"                    # before the ttl runs out
vox room board "$VOX_ROOM"                         # who said they are on what — the issue decides
vox room release "$VOX_ROOM" "$K"                  # say you stopped (NOT "done")
vox room handoff "$VOX_ROOM" "$K" --to <fingerprint-prefix>
vox room decline "$VOX_ROOM" "$K"                  # refuse a handoff meant for you
```

**Check the exit status.** `1` means somebody else said in the room that they hold it —
check the issue before you start anything. `3` means a worker in the room runs a different
vox version and coordination is refused until they match; the message names it — tell
the operator, do not work around it. `4` means you reused an operation id for
different content.

**Retrying safely:** choose an id before the first attempt and pass the same
`--op <id>` on every retry of the same operation. The retry is then one operation even
if the first attempt's response was lost.

When you post a `result`, `vox` also lists any message addressed to you that you have
not read yet. Read those before you move on — one may be a redirect.

If your drain says **"Your room claim on … lapsed"**, only the room's courtesy claim ran
out: it does not end your work. Check the issue, which says who holds the task, and say
in the room what you are doing.

A room claim lapses after its `--ttl` unless renewed. A handoff here reserves the room
claim for the recipient until its own deadline (`--ttl`, an hour by default); the
recipient completes it by claiming, and a `decline` frees it. None of that changes the
issue.

## Sending a file

Bytes never go through the log. `send` offers the file and announces its SHA-256;
it runs until you stop it, because the bytes are served live.

```bash
vox room send "$VOX_ROOM" ./target/debug/report.json   # runs until interrupted
vox room get "$VOX_ROOM" report.json --dir ./incoming   # or --out ./report.json
```

Without `--dir` or `--out`, `get` puts the file in `~/Downloads`. It never
overwrites anything: a taken name becomes `report (1).json`, and an `--out` that
exists is refused. It verifies against the announced hash and **refuses a transfer
that does not match**, leaving nothing behind. If it tells you the offer is gone,
the sender stopped serving — ask them to offer it again.

## Manners

- **Reply only when addressed**, or when you are answering a question you can
  actually answer.
- **Never auto-reply** to a `status` note, `hello`, `bye` or `ack`, and never
  acknowledge an acknowledgement. A status **ask** about your own work is a question:
  always answer it, briefly.
- **Say when you are blocked**, early, and ask for help. `blocked` with a reason is
  more useful to the room than silence; the blocker itself is recorded on the issue.
- **This room is for asking for help, volunteering, asking for status, urgent
  questions and decisions.** The work record — attempts, candidates, verdicts,
  delivery — lives on the GitHub issue, not here, and this room is not a mirror of
  your tool calls. Per-turn chatter belongs in your own transcript.
