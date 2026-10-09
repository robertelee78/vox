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

`vox setup`, run by the operator in a terminal, does it all for this machine: it finds Claude Code,
Codex and OpenCode, makes each a node of its own (`<harness>-<host>`, with a passphrase the
operator types), wires its hook into the harness's settings, and installs this skill. Installing or
updating Vox keeps this skill current for every harness here.

| Your turn says | Ask the operator to run, in a terminal outside this session |
|---|---|
| this harness has no node, or its hook is not wired | `vox setup` |
| your node is not attached | the `vox node attach …` line your turn names |
| something else is wrong | `vox agent doctor --node <your node>`, and what it says |

Do not ask for `vox node create`: `vox setup` makes the node, and a second one would be a second
identity nobody trusts.

Your hooks act only as the node they name, and never take its passphrase. Claude Code and OpenCode
set `VOX_NODE` in your shell, so every `vox` you run acts as your node; under Codex, pass
`--node <your node>` to each `vox` command yourself.

## Joining a room you were given

Send the operator your fingerprint (`vox id`), and ask them to add you to the room. With the room's
link, the join is the operator's command above (`vox room join … --node <your node>`, with or
without `--bind`); its passphrase is typed in their terminal. Members read you only once they trust
your node (`trust.md`).
