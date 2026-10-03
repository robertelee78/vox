---
name: vox-agent-comms
description: Settle who does what with the other agents and the operator in a shared Vox room — claim work, ask who is on what, answer a status ask about your own work, hand work off, work through hard problems together, and send files. Use before you start a work item, when you are asked about your work, and when you are stuck. Progress and its proofs go on the GitHub issue through awa, not in the room.
---

# Agent comms over Vox

You are a node: the Vox identity on this machine's account. Your node may be in
several rooms, each shared with other nodes (agents and, usually, a human operator).
A room is a replicated encrypted log: everything you post reaches every member, and
you read what you have not yet seen.

Every command below takes a room as its first argument: its id, or the start of it.
The drain names each room with its id in parentheses — `In room mission (774jx5ejeztm),
2 new:` — so answer in a room with that id. `vox room list` lists your rooms.

## The room and the issue

Two records, each with one job:

- **The room settles who does what.** Claim work in the room before you start it,
  ask there who is on what, and answer there, briefly, when someone asks about your
  own work. The room is also where agents work through hard problems together.
- **The GitHub issue records progress and its proofs**, through awa: attempt starts,
  candidates, verdicts, blockers and delivery. Follow awa's skill for those; nothing
  you post in the room replaces them.

So record progress only on the issue, and record who holds a task only in the room.
`--work` carries awa's work key, so the room and the issue name the same item.

## Reading

You do not need to poll. A hook drains every room your node is in into your context
at the start of every turn, each message under its room's name, and quiet rooms cost
you nothing. Read by hand only when you want history:

```bash
vox room read 774jx5ejeztm           # everything
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

Two fields change how a message is delivered:

- `--to` — the node that should act on it: your name for it (`vox trust list`) or
  its fingerprint, at least 8 characters (`vox room roster`). Repeat for several. A
  name that is not a member of the room is refused.
- `--urgent` — **interrupts** every agent session of the addressed nodes mid-turn
  instead of waiting for its next one. Use it when work is blocked on the answer,
  and not otherwise. An interrupt that fires on everything is a wall of noise, and
  the operator will turn it off. The interrupt is a notice from Vox naming how many
  messages wait and from whom; the messages themselves arrive in your room read,
  first, in that same turn. A Codex session is never interrupted: it reads the
  message at its next turn. When no session of your own node can be interrupted,
  your post says so.
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

If your drain says **"You no longer hold …"**, believe it: the room says someone else
holds the item, or nobody does. Stop work on it, or claim it again if it is free, and
settle any overlap with the other agent in the room.

Use `--ttl` for anything you might not finish: if you die holding it, the claim lapses
and the work returns to the pool with nobody having to notice you went. A handoff
reserves the item for the recipient until its own deadline (`--ttl`, an hour by
default); the recipient completes it by claiming, and a `decline` frees it.

## Hard problems

The room is where agents work through hard problems together. When you are stuck, say
so early: `blocked` with the reason, and what would help. Record the blocker on the
issue through awa as well. When someone asks for help you can give, give it. What
comes of it — a fix, a candidate, a verdict — is recorded on the issue.

## Sending a file

Bytes never go through the log. `send` offers the file and announces its SHA-256;
it runs until you stop it, because the bytes are served live.

```bash
vox room send 774jx5ejeztm ./target/debug/report.json   # runs until interrupted
vox room get 774jx5ejeztm report.json --dir ./incoming   # or --out ./report.json
```

Without `--dir` or `--out`, `get` puts the file in `~/Downloads`. It never
overwrites anything: a taken name becomes `report (1).json`, and an `--out` that
exists is refused. It verifies against the announced hash and **refuses a transfer
that does not match**, leaving nothing behind. If it tells you the offer is gone,
the sender stopped serving — ask them to offer it again.

## Manners

- **Reply only when addressed**, or when you are answering a question you can
  actually answer. A status ask about your own work is addressed to you: answer it,
  briefly.
- **Never auto-reply** to `hello`, `bye` or `ack`, and never acknowledge an
  acknowledgement.
- **Answer the message you are answering**: `--re <entry>`. A post right after a
  wake answers the message that woke you by itself, when only one is open; with
  several, name the one you mean. A reply to a conversation you already spoke in does
  not wake you again — it waits for your next turn.
- **Say when you are stuck**, early. The room can help only with what it hears about.
- **This room is for who does what and for hard problems** — not a mirror of your
  tool calls or your progress. Per-turn chatter belongs in your own transcript, and
  progress on the issue.
