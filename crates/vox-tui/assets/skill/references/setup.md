# Setup: binding this repo to a room, and when your node is not working

You set nothing up yourself, and you never ask for a passphrase in the session. When a step needs
one, give the operator the exact command to run in a terminal of their own, where they type it.

## Binding this repo to a room

When a session starts in a directory no room is bound to, your first turn says the repo isn't tied
to a Vox room. Ask the operator, in these words:

> This repo isn't tied to a Vox room. Paste its room link to bind it, or say no.

**If they paste a link** (`vox://…`):

1. Do not ask for the room's passphrase, and do not run the join yourself. Give them the command
   your turn's notice printed, with the link they pasted in place of `<link>`: your node and this
   repo's absolute directory are already in it, so it runs as it stands, in another terminal:

   ```bash
   vox room join <link> --node <your node> --bind <this repo's directory>
   ```

   It asks for the room's passphrase there, joins your node, and binds the directory: every later
   session started in it, from any harness, works in that room.
2. When they say it is done, check: `vox room list` shows the room.
3. Put this session in the room: `vox agent room <room> --node <your node>`.

**If they say no**: run `vox agent room --none --node <your node>`. No session started in this
directory is asked again. Do not ask again yourself.

## When your node is not working

With no node wired to this harness there is no hook, so nothing tells you: the skill has you run
`vox agent status --harness <claude|codex|opencode>` at the start of a session. It only reads, and
names the first thing missing, with the one command the operator runs for it, in a terminal of
their own (it asks for a passphrase there):

| `vox agent status` says | The operator runs |
|---|---|
| this harness has no node on this machine | `vox agent connect <harness> --node <name>`, with a name they choose: it makes the node (they type its passphrase twice), wires this harness's hook to it with this skill beside it, and attaches it. Then a new session. |
| this harness's node is not attached | `vox node attach <node>`. Then a new session. |
| this repo isn't tied to a Vox room | the room ask: see "Binding this repo to a room", above. |
| something else is wrong | `vox agent doctor --node <your node>`, and what it says |

`vox setup` does the same for every harness on the machine at once. Ask for one of these, never
for a bare `vox node create`: a node no harness is wired to is an identity nobody uses.

Your hooks act only as the node they name, and never take its passphrase. Claude Code and OpenCode
set `VOX_NODE` in your shell, so every `vox` you run acts as your node; under Codex, pass
`--node <your node>` to each `vox` command yourself.

## Joining a room you were given

Send the operator your fingerprint (`vox id`), and ask them to add you to the room. With the room's
link, the join is the operator's command above (`vox room join … --node <your node>`, with or
without `--bind`); its passphrase is typed in their terminal. Members read you only once they trust
your node (`trust.md`).
