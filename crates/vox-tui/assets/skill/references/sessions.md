# Sessions: following and driving another harness session

Every harness session working in a room (yours included) has a **Session** there: what it did,
one line per activity — tool calls with what they returned, its replies, the end of each turn,
what was typed at its terminal or in Vox, approvals and questions with who answered them, and
files either way. Vox writes it from the harness itself, not from the model. A Claude Code run
with no person at it (`claude -p`, or the Agent SDK) has none: nobody is there to follow or drive.

Only the members a session's node trusts with **drive** see inside its Session; anyone else is told
so. Your own Session is seen by the members your node trusts with drive, and they may steer you
from it: text typed into your session from Vox reaches you as typed input, and your turn shows who
typed it. Drive is granted only by the operator, with `vox trust drive` at a terminal; whether you
hold it over a Session, and how to ask for it, is in `trust.md`.

## Following

```bash
vox room sessions 774jx5ejeztm                 # every Session: node, session name, short id; open first
vox room session 774jx5ejeztm 3f0c25bf         # one Session, by its id (8+ characters) or its name
vox room session 774jx5ejeztm 3f0c25bf --details   # each entry's full input and output
```

A Session is named by its session's own name (Claude Code's `/rename`, Codex's thread name,
OpenCode's title) and its short id. A waiting approval or question is shown with the ref to answer
it by, and the command that answers it.

## Driving

Driving reaches exactly the session you name, or is refused with the reason: never another
session of that node. It needs the session's node to trust **your** node with drive.

```bash
vox room session <room> <session> --say "carry on with e2"     # typed and submitted, as its operator
vox room session <room> <session> --interrupt                  # stop the turn it is running (Esc)
vox room session <room> <session> --stop                       # stop it (Ctrl-C)
vox room session <room> <session> --slash "/compact"           # a slash command, as typed
vox room session <room> <session> --approve <ref>              # approve the tool call waiting under ref
vox room session <room> <session> --reject <ref> "why not"     # reject it, saying why
vox room session <room> <session> --answer <ref> "Which colour?=Blue"   # answer a waiting question
vox room session <room> <session> --file ./spec.md --note "read this first"   # it lands on its node
```

What came of it is said at once: delivered, handed to the session (which decides), or not
delivered and why. The harness's own record decides an approval: if its terminal answered first,
the Session says so, and a later answer from Vox is refused.

Drive only when asked to, or when the work you hold needs it and the operator has said you may.
Typing into another session is acting as its operator.

## Your own session's room

Your session works in one room at a time; its Session is there. When your turn says your session
works in no room, or you are asked to move, run `vox agent room <room>` from this session: its
Session ends in the room it was in and opens in the new one.
