// vox — OpenCode plugin (ADR-020 §6). Drains this session's Vox room at the top of
// every turn and injects what it finds, so an agent reads its room whether or not
// the model would have thought to.
//
// Install:
//   vox agent plugin opencode > ~/.config/opencode/plugin/vox.js
//   export VOX_ROOM=<room id or unique prefix>
//
// This is a shim, not a second implementation. Everything that decides what an
// agent has not yet read — attaching to the node, resolving the room, the cursor,
// what counts as unread — lives in `vox agent hook`, exactly as it does for Claude
// Code and Codex. The only thing that differs per harness is the shape of the
// injected context, and OpenCode's shape is a text part on the user message. So
// this reads `--format text`, the same plain stdout Codex takes.
//
// ## Measured against OpenCode 1.18.31 with a live model, not read from docs
//
// The plugin API is undocumented and its failure modes are silent: the plugin
// appears to do nothing, and the turn either answers without the injection or
// produces no output at all. What is stated here was measured; where something was
// believed and then disproved, it says so.
//
//   - **Rewrite an existing text part; never append a new one.** Pushing a part
//     hangs the turn indefinitely, with and without a completed `time` field, and
//     prints nothing on either stream. Appending would also need an id beginning
//     `prt`, or the turn dies with a `SchemaError` surfacing as a nameless
//     `UnknownError`. Rewriting in place avoids both, and is why no id is minted.
//   - **Running `vox` through Bun's `$`**, which arrives on the plugin input, is
//     the API OpenCode provides for this, and it means no child-process module is
//     imported at all. It is also why `vox agent hook` has a `--session` flag:
//     with no child process to pipe, there is no stdin to carry the session id on.
//     (An earlier version of this comment claimed importing `node:child_process`
//     breaks the turn. **That was wrong** — a control run without the import
//     failed identically. The real cause was the environment; see below.)
//   - **OpenCode installs a `node_modules` tree** into both `.opencode/` in the
//     project and `$XDG_CONFIG_HOME/opencode/` the first time it is used there.
//     Until that has happened the plugin may load while its hook never fires, so
//     a brand-new directory can behave differently from a working one.
//   - **When spawning OpenCode from a test or a tool, clear the environment.** A
//     spawned OpenCode that inherits `cargo test`'s environment loads this plugin
//     and **never fires `chat.message`**; run from a shell, in the same directory
//     with the same arguments and stdin, it works. Passing only `PATH`, `HOME`,
//     `SHELL`, `LANG`, `TMPDIR` and `USER` fixes it. This does not affect an
//     operator running `opencode` normally.
//   - Touching the OpenCode client inside plugin init deadlocks the TUI — reported
//     by ctm's own plugin, not measured here. This file never touches the client,
//     so it is safe in the TUI as well as headless.
//
// Every failure path is silent and injects nothing. A hook that breaks the turn it
// rides on is worse than one that does nothing.

import { appendFileSync } from "node:fs"

/**
 * Opt-in diagnostics: `VOX_PLUGIN_LOG=/path/to/file`.
 *
 * Every other path here is deliberately silent, because a plugin that throws
 * breaks the turn it rides on. The cost of that silence is that a misconfigured
 * install looks exactly like a quiet room. This tells them apart, and is off
 * unless asked for.
 */
function log(line) {
  const path = process.env.VOX_PLUGIN_LOG
  if (!path) return
  try {
    appendFileSync(path, new Date().toISOString() + " " + line + "\n")
  } catch {}
}

export default async function vox({ $ }) {
  log("plugin loaded (cwd=" + process.cwd() + ")")
  return {
    "chat.message": async (input, output) => {
      try {
        const sessionID = output.message?.sessionID || input.sessionID
        if (!sessionID) {
          log("chat.message: no session id")
          return
        }
        const room = process.env.VOX_ROOM
        if (!room) {
          log("chat.message: VOX_ROOM is unset")
          return
        }
        const bin = process.env.VOX_BIN || "vox"

        // `.quiet()` keeps the child's output out of OpenCode's, `.nothrow()`
        // makes a non-zero exit a value rather than an exception — `vox agent
        // hook` always exits 0, but a missing binary would otherwise throw.
        const result =
          await $`${bin} agent hook --format text --room ${room} --session ${sessionID}`
            .quiet()
            .nothrow()
        const text = result.stdout.toString()
        log("drain: exit=" + result.exitCode + " bytes=" + text.length)

        // A quiet room injects nothing at all — not "no new messages". A quiet
        // room should cost zero tokens per turn.
        if (!text.trim()) {
          log("chat.message: nothing to inject")
          return
        }

        // Fenced, so the model can tell what came from the room from what the
        // operator actually typed. Prepended rather than appended: it is context
        // for the prompt that follows, the same position Claude Code's
        // `additionalContext` occupies.
        const block = "<vox-room>\n" + text.trim() + "\n</vox-room>\n\n"
        for (const part of output.parts) {
          if (part.type === "text" && typeof part.text === "string") {
            part.text = block + part.text
            log("chat.message: injected " + text.trim().length + " chars")
            return
          }
        }
        log("chat.message: no text part to inject into")
      } catch (e) {
        // Injecting nothing is always better than failing the turn.
        log("chat.message: threw: " + e)
      }
    },
  }
}
