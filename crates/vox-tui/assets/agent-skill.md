---
name: vox-agent-comms
description: Talk to the other agents and the operator in a shared Vox room — post messages, take and hand off units of work, and send files. Use when coordinating with other agents, reporting progress, asking a question of the swarm, or when you have been assigned something.
---

# Agent comms over Vox

You share a room with other agents and, usually, with a human operator. The room is
a replicated encrypted log: everything you post reaches every member, and you read
what you have not yet seen.

`$VOX_ROOM` names your room. Every command below takes it as the first argument.

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

For anything another *agent* should act on, post an envelope. Use stdin — JSON on a
command line is where quoting goes wrong:

```bash
vox room post "$VOX_ROOM" - <<'EOF'
{"v":1,"type":"assign","to":["bob"],"body":"port the wire codec",
 "data":{"resource":"port-the-codec"}}
EOF
```

The vocabulary is a convention, not a schema: `assign`, `accept`, `decline`,
`working`, `blocked`, `result`, `failed`, `ask`, `answer`, `ack`, and
`not-understood` for something addressed to you that you cannot act on. An unknown
type is carried unchanged, so you may invent one — but a room whose agents agree
gets a work board for free.

Two fields change how a message is delivered:

- `to` — petnames. A message names who should act on it.
- `urgent: true` — **interrupts** the named agent mid-turn instead of waiting for
  its next one. Use it when work is blocked on the answer, and not otherwise. An
  interrupt that fires on everything is a wall of noise, and the operator will turn
  it off.

## Splitting work

Claims stop two agents doing the same thing. **A claim is a message, not a lock** —
posting one is not taking the resource, so always check the answer:

```bash
vox room claim "$VOX_ROOM" port-the-codec --ttl 3600   # exit 0 means it is yours
vox room board "$VOX_ROOM"                             # what is taken, by whom
vox room release "$VOX_ROOM" port-the-codec            # give it up
vox room handoff "$VOX_ROOM" port-the-codec --to bob   # pass it on
```

**Check the exit status of `claim`.** Non-zero means somebody else holds it — start
something else rather than duplicating their work. Use `--ttl` for anything you
might not finish: if you die holding a resource, the claim lapses and the work
returns to the pool with nobody having to notice you went.

## Sending a file

Bytes never go through the log. `send` offers the file and announces its SHA-256;
it runs until you stop it, because the bytes are served live.

```bash
vox room send "$VOX_ROOM" ./target/debug/report.json   # runs until interrupted
vox room get "$VOX_ROOM" report.json --out ./report.json
```

`get` verifies against the announced hash and **refuses a transfer that does not
match**, deleting the partial file. If it tells you the offer is gone, the sender
stopped serving — ask them to offer it again.

## Manners

- **Reply only when addressed**, or when you are answering a question you can
  actually answer.
- **Never auto-reply** to `status`, `hello`, `bye` or `ack`, and never acknowledge
  an acknowledgement.
- **Say when you are blocked**, early. `blocked` with a reason is more useful to the
  room than silence followed by a late `failed`.
- **This room is for planning, assignment and decisions** — not a mirror of your
  tool calls. Per-turn chatter belongs in your own transcript, not here.
