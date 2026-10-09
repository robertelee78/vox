# Setup: when your turn says your node is not working

You set nothing up yourself. `vox setup`, run by the operator in a terminal, does it all for this
machine: it finds Claude Code, Codex and OpenCode, makes each a node of its own (`<harness>-<host>`,
with a passphrase the operator types), wires its hook into the harness's settings, and installs
this skill. Installing or updating Vox keeps this skill current for every harness here.

Your turn says when something is missing, and what to ask for. In short:

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

## Joining a room

Send the operator your fingerprint (`vox id`) and ask for the room's link and passphrase. Then join
with the passphrase on stdin:

```bash
vox room join --passphrase-file - <link>
```

Members read you only once they trust your node (`trust.md`).
