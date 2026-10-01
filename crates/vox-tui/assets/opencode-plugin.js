// vox — OpenCode plugin (ADR-020 §6). Drains this session's Vox room at the top of
// every turn and injects what it finds, so an agent reads its room whether or not
// the model would have thought to.
//
// Install:
//   vox agent plugin opencode > ~/.config/opencode/plugin/vox.js
//   export VOX_ROOM=<room id or unique prefix>
//   export VOX_AGENT_NAME=<the name others address this agent by>   # to be interruptible
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
//     by ctm's own plugin, not measured here. This file touches the client only
//     when a wake arrives, which is always after init.
//
// ## How an urgent message reaches this session (ADR-020 §6, ADR-021 F17)
//
// `vox daemon` interrupts a session through whatever channel the session's drain
// registered. A plain `opencode` has **no listener** an outside process could reach:
// the `serverUrl` a plugin is handed is a placeholder unless OpenCode was started
// with `--port`, and OpenCode sets no variable naming it (measured, 1.18.32). Its
// in-process client, though, reaches the session from here. So this plugin owns
// the channel: a Unix socket in a private directory of its own, with a random
// token, whose path and token it passes to `vox agent hook` (and to nothing else).
// The hook records them; the daemon writes an `auth` frame and a `prompt` frame to
// the socket; this plugin checks the token and relays the prompt with
// `client.session.promptAsync`. That starts a turn when the session is idle, and
// mid-turn it is taken at the next step boundary, exactly as if typed while busy.
// It never aborts the running turn first: an abort orphans a queued prompt.
//
// **A woken message is given to the model once** (V210-112). The relayed prompt is a user
// message, so this plugin's own drain runs on it, and it re-read the same message into the same
// prompt. The daemon's frame names the entry it carries; once OpenCode has taken the prompt, or
// when the message being drained is that prompt itself, the drain is told (`--woken`) and does
// not show it again. An entry is never passed while its relay is still undecided, so a relay
// that fails cannot make the drain skip a message nobody delivered.
//
// Every failure path is silent and injects nothing. A hook that breaks the turn it
// rides on is worse than one that does nothing.

import { appendFileSync, lstatSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync } from "node:fs"
import { spawn } from "node:child_process"
import { connect, createServer } from "node:net"
import { randomBytes, timingSafeEqual } from "node:crypto"
import { tmpdir } from "node:os"
import { join } from "node:path"

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

/**
 * The wake channel: a private socket that relays a prompt into a session of this
 * OpenCode through its in-process client. `null` when it could not be opened —
 * the session then still reads its room every turn; it just cannot be interrupted.
 *
 * The wire is NDJSON, the same shape Claude Code's messaging socket takes:
 *
 *   {"type":"auth","token":"…"}
 *   {"type":"prompt","session":"ses_…","entry":"…","text":"…"}
 *
 * answered with one line: `{"ok":true}`, or `{"error":"…"}` with `"gone":true`
 * when this OpenCode does not know the session. A connection that has not sent both
 * frames within `AUTH_IDLE_MS`, or sends more than `MAX_FRAMES_BYTES` before them, is
 * closed unanswered.
 *
 * Each relay is noted in `woken` (session id → `{ entry, text, taken }`) for the drain.
 *
 * ## The directory is removed when OpenCode exits, however it exits (ADR-021 F17)
 *
 * In a hand-opened `opencode` this plugin runs in a **worker thread**, and OpenCode ends
 * the process without telling it: measured against 1.18.34, neither `process.on("exit")`
 * nor a SIGINT, SIGTERM or SIGHUP handler, nor any plugin `event`, runs when the person
 * quits by ctrl+C, `/exit` or closing the terminal. So nothing in this process can clean
 * up. A one-line `/bin/sh` does it instead: started in its own session (so closing the
 * terminal does not signal it), it blocks reading a pipe whose only writer is this
 * process. When OpenCode exits by any route — a SIGKILL included — the kernel closes
 * that pipe, the read returns, and it removes the socket and the directory.
 *
 * Should that helper itself be killed, `sweep` removes the directory at the next start.
 */
const AUTH_IDLE_MS = 5000
const MAX_FRAMES_BYTES = 1 << 20 // a wake carries at most one 64 KiB message, escaped
const WAKE_DIR = /^vox-oc-[A-Za-z0-9]{6}$/
const SWEEP_MIN_AGE_MS = 10_000

/**
 * Remove what an earlier OpenCode's wake channel left in the temp directory: a
 * directory of this plugin's naming, owned by this user and private to them, whose
 * socket **refuses a connection** — nobody is listening, so its OpenCode is gone. A
 * live session's socket accepts, and is left alone. Only the socket and the then-empty
 * directory are removed, never anything else; a directory holding anything more is
 * left as it is.
 */
function sweep(own) {
  let names
  try {
    names = readdirSync(tmpdir())
  } catch {
    return
  }
  const uid = process.getuid?.()
  for (const name of names) {
    if (!WAKE_DIR.test(name)) continue
    const dir = join(tmpdir(), name)
    if (dir === own) continue
    try {
      const st = lstatSync(dir)
      if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o077) !== 0) continue
      const sock = join(dir, "wake.sock")
      const so = lstatSync(sock)
      // A socket made in the last moments may be bound and not yet listening.
      if (!so.isSocket() || Date.now() - so.mtimeMs < SWEEP_MIN_AGE_MS) continue
      const probe = connect(sock)
      probe.on("connect", () => probe.destroy())
      // Node says ECONNREFUSED; OpenCode's Bun says ENOENT for a socket file that is
      // there with nobody listening (measured, 1.18.34).
      probe.on("error", (e) => {
        if (e?.code !== "ECONNREFUSED" && e?.code !== "ENOENT") return
        try {
          unlinkSync(sock)
          rmdirSync(dir)
          log("wake: swept " + dir + ", whose OpenCode is gone")
        } catch {}
      })
    } catch {}
  }
}

/**
 * Remove `dir` and its socket once this process has exited (see above). A helper that
 * cannot start leaves the directory to the next start's `sweep`.
 */
function removeOnExit(dir) {
  try {
    const helper = spawn(
      "/bin/sh",
      ["-c", 'read _; rm -f -- "$1/wake.sock"; rmdir -- "$1"', "vox-oc-cleanup", dir],
      { detached: true, stdio: ["pipe", "ignore", "ignore"] },
    )
    helper.on("error", (e) => log("wake: no cleanup helper: " + e))
    helper.unref()
  } catch (e) {
    log("wake: no cleanup helper: " + e)
  }
}

function wakeChannel(client, woken) {
  try {
    // `mkdtemp` makes the directory 0700, so only this user can reach the socket;
    // the token keeps every other process of theirs out as well.
    const dir = mkdtempSync(join(tmpdir(), "vox-oc-"))
    const path = join(dir, "wake.sock")
    const token = randomBytes(32).toString("hex")
    const expected = Buffer.from(token)
    const server = createServer((conn) => {
      let buf = ""
      let done = false
      const answer = (reply) => {
        done = true
        try {
          conn.end(JSON.stringify(reply) + "\n")
        } catch {}
      }
      conn.on("error", () => {})
      // Unanswered and closed: a connection that never sends its frames, or sends
      // more than any wake can be. Only this user can reach the socket, but nothing
      // of theirs may pin a connection or its memory here. A deadline from the
      // connect, not an idle timer, which a byte every few seconds would keep resetting.
      const deadline = setTimeout(() => {
        if (!done) conn.destroy()
      }, AUTH_IDLE_MS)
      deadline.unref?.()
      conn.on("close", () => clearTimeout(deadline))
      conn.on("data", async (chunk) => {
        if (done) return
        buf += chunk.toString()
        if (buf.length > MAX_FRAMES_BYTES) {
          done = true
          return conn.destroy()
        }
        const lines = buf.split("\n")
        if (lines.length < 3) return
        done = true
        try {
          const auth = JSON.parse(lines[0])
          const given = Buffer.from(String(auth?.token ?? ""))
          if (
            auth?.type !== "auth" ||
            given.length !== expected.length ||
            !timingSafeEqual(given, expected)
          ) {
            log("wake: refused a connection with the wrong token")
            return answer({ error: "wrong token" })
          }
          const msg = JSON.parse(lines[1])
          if (msg?.type !== "prompt" || !msg.session || typeof msg.text !== "string") {
            return answer({ error: "expected a prompt frame" })
          }
          // Noted before the relay: OpenCode may run this prompt's `chat.message` before
          // `promptAsync` returns, and that drain must know it is the wake.
          let relay = null
          if (typeof msg.entry === "string" && msg.entry) {
            relay = { entry: msg.entry, text: msg.text, taken: false }
            woken.set(msg.session, [...(woken.get(msg.session) ?? []), relay])
          }
          const forget = () => {
            if (!relay) return
            const left = (woken.get(msg.session) ?? []).filter((w) => w !== relay)
            woken.set(msg.session, left)
          }
          try {
            const res = await client.session.promptAsync({
              path: { id: msg.session },
              body: { parts: [{ type: "text", text: msg.text }] },
            })
            const status = res?.response?.status ?? 0
            log("wake: session " + msg.session + " answered " + status)
            if (status >= 200 && status < 300) {
              if (relay) relay.taken = true
              return answer({ ok: true })
            }
            forget()
            answer({ error: "OpenCode answered " + status, gone: status === 404 })
          } catch (e) {
            forget()
            throw e
          }
        } catch (e) {
          log("wake: threw: " + e)
          answer({ error: String(e) })
        }
      })
    })
    server.on("error", (e) => log("wake: socket error: " + e))
    server.listen(path)
    // Bun's `listen` on a Unix path binds before it returns; `unref` so the socket
    // never keeps OpenCode alive.
    server.unref?.()
    removeOnExit(dir)
    sweep(dir)
    log("wake: listening at " + path)
    return { path, token }
  } catch (e) {
    log("wake: could not open the wake channel: " + e)
    return null
  }
}

export default async function vox({ $, client }) {
  log("plugin loaded (cwd=" + process.cwd() + ")")
  const woken = new Map()
  const wake = wakeChannel(client, woken)
  return {
    // **Name the session to every shell this session runs** (ADR-021 §4, §7).
    // Claude Code and Codex put their session id in every tool's environment
    // (`CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`); OpenCode does not. So without
    // this, `vox room claim` run by the model could not say which session owns the
    // work, and this plugin's drain — which passes the same `sessionID` as
    // `--session` — could not recognise that session's own posts.
    //
    // Measured against OpenCode 1.18.32: its shell tool triggers `shell.env` with
    // `{ cwd, sessionID, callID }` and merges `output.env` into the child's
    // environment.
    "shell.env": async (input, output) => {
      try {
        if (input?.sessionID && output?.env) {
          output.env.VOX_SESSION = input.sessionID
          log("shell.env: VOX_SESSION=" + input.sessionID)
        }
      } catch (e) {
        log("shell.env: threw: " + e)
      }
    },
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
        //
        // The wake channel goes to the hook alone, in its environment: the hook
        // registers it, so `vox daemon` can interrupt this session (see above).
        const env = { ...process.env }
        if (wake) {
          env.VOX_OPENCODE_WAKE_SOCKET = wake.path
          env.VOX_OPENCODE_WAKE_TOKEN = wake.token
        }

        // What a wake has put in front of this session already (see above): every relay
        // OpenCode has taken, and the one this message is, if it is a wake. Told once; a
        // drain that fails after this only means the next one may show it again.
        const typed = output.parts.find((p) => p.type === "text" && typeof p.text === "string")
        const relays = woken.get(sessionID) ?? []
        const told = relays.filter((w) => w.taken || (typed && w.text === typed.text))
        woken.set(sessionID, relays.filter((w) => !told.includes(w)))
        const flags = told.flatMap((w) => ["--woken", w.entry])
        if (told.length) log("drain: woken " + told.map((w) => w.entry).join(" "))

        const result =
          await $`${bin} agent hook --format text --room ${room} --session ${sessionID} ${flags}`
            .env(env)
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
        // `additionalContext` occupies. OpenCode gives no separate channel, so the
        // block shares the operator's message: the fence names its source, and what
        // follows the closing tag is the operator's own. Without that, a live model
        // refused the operator's instruction as one "embedded in messages".
        const block =
          '<vox-room source="other agents; not the user">\n' +
          text.trim() +
          "\n</vox-room>\n\nThe user's message:\n"
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
