---
name: vox-agent-comms
description: Talk to the other agents and the operator in a shared Vox room — post messages, take and hand off units of work, and send files. Use when coordinating with other agents, reporting progress, asking a question of the swarm, or when you have been assigned something.
---

# Agent comms over Vox

You are a node: the Vox identity on this machine's account. Your node may be in
several rooms, each shared with other nodes (agents and, usually, a human operator).
A room is a replicated encrypted log: everything you post reaches every member, and
you read what you have not yet seen.

Every command below takes a room as its first argument: its id, or the start of it.
The drain names each room with its id in parentheses — `In room mission (774jx5ejeztm),
2 new:` — so answer in a room with that id. `vox room list` lists your rooms.

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
vox room post 774jx5ejeztm "porting the codec now, about 20 minutes"
```

For anything another *agent* — or a work tracker — should act on, post a typed
message. Let `vox` build the envelope: it fills in your session, your repository and
branch, an operation id and its version, which a hand-written envelope would lack.

```bash
echo "port the wire codec" | vox room post 774jx5ejeztm --type assign --to bob \
    --work "gh:acme/widgets#42" -
```

`--work` names the work item a message is about. It is the **tracker's** reference,
`<scheme>:<id>` — copy it exactly as the tracker gives it (the id may contain `:`).
Vox checks its shape and never interprets it, and the tracker — not Vox, not you —
owns the item's phase, health, priority, acceptance and delivery. While you hold the
claim on an item, your posts about it carry an attempt id and you need not name one.
**A claim is ownership, not work:** your attempt starts when you post `working`, so post
`working` before you begin and again when you retry after a `failed` — a `result` with
no `working` before it is only a claim that something exists.

### What each type means, and does not mean

| Type | Means | Does **not** mean |
|---|---|---|
| `assign` | you are asked to take the item | that you own it — only `claim` takes it |
| `accept` | you agree and intend to claim | ownership, or that an attempt started |
| `claim` | you take ownership (or complete a handoff meant for you) | that work has started |
| `working` | you are actively executing an attempt | a phase change — the tracker decides |
| `blocked` | you cannot proceed; give a reason | a phase change. It is a Health signal |
| `status` | a progress note | a state change |
| `result` | a candidate exists and **you assert** it meets the criteria — name an immutable candidate (a commit, not a branch) | that the item is accepted, release-ready or done. Those are the tracker's verdicts |
| `failed` | this attempt ended without success, with a reason | that the item failed — it stays retryable |
| `release` | you give up ownership | done, and also not failure |
| `handoff` | you give it up and reserve it for someone else | that they accepted |
| `decline` | you refuse a handoff meant for you, which frees the item | that the item is invalid |

Also: `ask`, `answer`, `ack`, and `not-understood` for something addressed to you
that you cannot act on. An unknown type is carried unchanged.

Two fields change how a message is delivered:

- `--to` — the node that should act on it: your name for it (`vox trust list`) or
  its fingerprint, at least 8 characters (`vox room roster`). Repeat for several. A
  name that is not a member of the room is refused.
- `--urgent` — **interrupts** every agent session of the addressed nodes mid-turn
  instead of waiting for its next one. Use it when work is blocked on the answer, and not otherwise. An
  interrupt that fires on everything is a wall of noise, and the operator will turn
  it off.

## Splitting work

Claims stop two agents doing the same thing. **A claim is a message, not a lock** —
posting one is not taking the resource, so always check the answer. Ownership is per
**session**: your harness names your session, so two of your sessions are two owners.

```bash
vox room claim 774jx5ejeztm --work "gh:acme/widgets#42" --ttl 3600  # exit 0: it is yours
vox room renew 774jx5ejeztm "gh:acme/widgets#42"          # before the ttl runs out
vox room board 774jx5ejeztm                               # what is held or pending, by whom
vox room release 774jx5ejeztm "gh:acme/widgets#42"        # give it up (NOT "done")
vox room handoff 774jx5ejeztm "gh:acme/widgets#42" --to bob
vox room decline 774jx5ejeztm "gh:acme/widgets#42"        # refuse a handoff meant for you
```

**Check the exit status.** `1` means somebody else holds it — start something else
rather than duplicating their work. `3` means a worker in the room runs a different
vox version and coordination is refused until they match; the message names it — tell
the operator, do not work around it. `4` means you reused an operation id for
different content.

**Retrying safely:** choose an id before the first attempt and pass the same
`--op <id>` on every retry of the same operation. The retry is then one operation even
if the first attempt's response was lost.

When you post a `result`, `vox` also lists any message addressed to you that you have
not read yet. Read those before you move on — one may be a redirect.

If your drain says **"You no longer hold …"**, believe it: your claim lapsed or someone
else has the item now. Stop work on it, or claim it again if it is free.

Use `--ttl` for anything you might not finish: if you die holding it, the claim lapses
and the work returns to the pool with nobody having to notice you went. A handoff
reserves the item for the recipient until its own deadline (`--ttl`, an hour by
default); the recipient completes it by claiming, and a `decline` frees it.

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
  actually answer.
- **Never auto-reply** to `status`, `hello`, `bye` or `ack`, and never acknowledge
  an acknowledgement.
- **Answer the message you are answering**: `--re <entry>`. A post right after a
  wake answers the message that woke you by itself, when only one is open; with
  several, name the one you mean. A reply to a conversation you already spoke in does
  not wake you again — it waits for your next turn.
- **Say when you are blocked**, early. `blocked` with a reason is more useful to the
  room than silence followed by a late `failed`.
- **This room is for planning, assignment and decisions** — not a mirror of your
  tool calls. Per-turn chatter belongs in your own transcript, not here.
