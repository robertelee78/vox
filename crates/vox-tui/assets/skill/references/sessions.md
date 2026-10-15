# Sessions: following and driving another harness session

Every harness session working in a room (yours included) has a **Session** there: what it did,
one line per activity — tool calls with what they returned, its replies, the end of each turn,
what was typed at its terminal or in Vox, approvals and questions with who answered them, and
files either way. Vox writes it from the harness itself, not from the model. A run with no person
at it has none: `claude -p` (or the Agent SDK), `codex exec`, `opencode run`. Nobody is there to
follow or drive.

Only the members a session's node trusts with **drive** see inside its Session. A read-only
viewer may have no selectable metadata row; a missing row is not proof that the harness ended.
When Drive is taken back, private queries refuse and the app retires the selected private surface.
Revocation cannot erase what someone already copied. Your own Session is seen by the members your node trusts with drive, and they may steer you
from it: text typed into your session from Vox reaches you as typed input, and your turn shows who
typed it. Whether you hold drive over a Session, how automatic local trust applies, and when a manual
operator grant is needed are in `trust.md`.

## Following

List Sessions with `vox room sessions`, the actual bound room and your node. It returns the
node, Session name and short ID, open first. Read the intended one with `vox room session`,
that room, its returned ID (8+ characters) or name, and your node. Add `--details` for full input
and output. Reads are bounded: use the actual `--before` continuation with the same selection
for older activity. Do not call a single page the whole Session. Construct these commands from
actual output using SKILL.md's quoting rule, including attached `--session=value` when a named
option's actual value could begin with a hyphen.

A Session is named by its session's own name (Claude Code's `/rename`, Codex's thread name,
OpenCode's title) and its short id. A waiting approval or question is shown with the ref to answer
it by, and the command that answers it.

## Private attention status

For an actual selected open Session with Drive, add `--attention` to its complete read command.
Use only its returned `--attention-after` cursor for continuation. Preparing, an error and unknown
acceptance are not complete empty results. Queued names its next-turn/pause/client reason;
Delivered confirms context, Answering an observed running turn, and Answered a correlated room
answer. A Claude context receipt alone does not show Answering. Never infer a promised reply or
retry an unknown wake. General does not expose this private report.

Room Pause holds automatic news and wakes; direct operator Drive stays available. Resume leaves
ordinary backlog for the next turn. Use pause/resume only within the operator's authorized scope,
with actual room and target nodes; inspect every receiver outcome, including saved-state versus
interruption failure.

## Driving

Driving reaches exactly the session you name, or is refused with the reason: never another
session of that node. It needs the session's node to trust **your** node with drive.

Start with the complete read command for that actual room, Session and your node, then add the
chosen input. Use the waiting request's real reference, never a sample ID:

| Input | Values and effect |
|---|---|
| `--say` | your text, typed and submitted as the operator |
| `--interrupt` | interrupt its running turn (Esc) |
| `--stop` | stop it (Ctrl-C) |
| `--slash` | the supported slash command you intend to send |
| `--approve` | exact reference of the tool call currently waiting |
| `--reject` | exact waiting reference, followed by your reason |
| `--answer` | exact waiting reference, followed by the actual question and chosen answer in the shown answer format |
| `--file` | an existing file path; `--note` adds your message; the file lands on the Session's node |

What came of it is said at once: delivered, handed to the session (which decides), or not
delivered and why. The harness's own record decides an approval: if its terminal answered first,
the Session says so, and a later answer from Vox is refused.

Drive only when asked to, or when the work you hold needs it and the operator has said you may.
Typing into another session is acting as its operator.

## Your own session's room

Your session works in one room at a time; its Session is there. Use this repository's saved room,
not another room the node holds. If it has no binding, follow `setup.md`; do not choose a room
yourself. Once the operator has selected the room or authorized a move, use `vox agent room`
with the selected room and this session's actual `--node` from this session: its Session ends in the old room and opens in the selected one.
