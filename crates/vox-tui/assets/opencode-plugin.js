// vox — OpenCode plugin (ADR-020 §6). Drains every Vox room this node holds at the top
// of every turn and injects what it finds, so an agent reads its rooms whether or not
// the model would have thought to.
//
// Install:
//   vox agent plugin opencode > ~/.config/opencode/plugin/vox.js
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
// **A wake carries no message** (V030-15). The relayed prompt is a notice from Vox: how many
// urgent messages and replies wait, from whom, in which room. The relayed prompt is a user
// message, so this plugin's own drain runs on it, and that drain is what gives the model the
// messages themselves, once, first in its block.
//
// ## How the session's Session is fed and driven (ADR-029 #542, #544)
//
// A second socket beside the wake socket, `mirror.sock`, with the same token, carries the
// Session. After its `auth` frame, a connection that sends
// `{"type":"subscribe","session":"ses_…"}` stays open: this plugin writes
// it every event of OpenCode's bus that belongs to that session or to a sub-agent's session
// under it (`{"type":"event","event":…}`), and runs the calls it sends back, each on that
// session alone (`{"type":"call","id":n,"action":…}` → `{"type":"result","id":n,"ok":…}`).
// What the events mean, and what reaches the Session, is decided in `vox daemon`, not here.
// A call names no session: it acts on the subscribed one, so input reaches exactly the session
// it is for (DR-5), and the actions are a whitelist, none of which starts a session (DR-7).
//
// Every failure path is silent and injects nothing. A hook that breaks the turn it
// rides on is worse than one that does nothing.

import { appendFileSync, lstatSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync } from "node:fs"
import { spawn } from "node:child_process"
import { connect, createServer } from "node:net"
import { randomBytes, timingSafeEqual } from "node:crypto"
import { StringDecoder } from "node:string_decoder"
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
 *   {"type":"prompt","session":"ses_…","text":"…"}
 *
 * answered with one line: `{"ok":true}`, or `{"error":"…"}` with `"gone":true`
 * when this OpenCode does not know the session. A connection that has not sent both
 * frames within `AUTH_IDLE_MS`, or sends more than `MAX_FRAMES_BYTES` before them, is
 * closed unanswered.
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
const MAX_FRAMES_BYTES = 1 << 20 // far more than any notice
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
          try {
            unlinkSync(join(dir, "mirror.sock"))
          } catch {}
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
      ["-c", 'read _; rm -f -- "$1/wake.sock" "$1/mirror.sock"; rmdir -- "$1"', "vox-oc-cleanup", dir],
      { detached: true, stdio: ["pipe", "ignore", "ignore"] },
    )
    helper.on("error", (e) => log("wake: no cleanup helper: " + e))
    helper.unref()
  } catch (e) {
    log("wake: no cleanup helper: " + e)
  }
}

/**
 * Room text with every `<vox-room` and `</vox-room` (any case) made inert (V030-21), so a message
 * cannot open or close a fence of its own: the `<` becomes `&lt;`. The fence's own tags are added
 * after this, and carry a nonce besides, so even a tag that slipped past could not end the block.
 */
function defang(text) {
  return text.replace(/<(\/?)(vox-room)/gi, "&lt;$1$2")
}

/** The most wake notices remembered per session until OpenCode runs a turn on them. */
const MAX_RELAYED = 16

// The agent's own node, written in by `vox agent plugin opencode --node <name>` (ADR-020 2.1): the
// drain hook acts only as it, and every shell this session runs names it in `VOX_NODE`, so the
// agent's `vox room …` act as its node too, never as a person's node on the same machine.
const VOX_NODE = "@VOX_NODE@"

/**
 * The connections following a session's Session: session id → the set of `write` functions.
 * A sub-agent's session is followed through its parent (`parents`: child id → parent id).
 */
const followers = new Map()
const parents = new Map()
/** Requests OpenCode asked (permission or question id → the Session it was shown in). */
const asked = new Map()
const MAX_ASKED = 1024

/** The session an event belongs to, and the Session it is shown in (its parent's, for a sub-agent). */
function ownerOf(event) {
  const p = event?.properties ?? {}
  const sid = p.sessionID ?? p.part?.sessionID ?? p.info?.sessionID ?? p.info?.id
  if (typeof sid !== "string") return null
  if ((event.type === "session.created" || event.type === "session.updated") && p.info?.parentID) {
    parents.set(p.info.id, p.info.parentID)
  }
  return parents.get(sid) ?? sid
}

function fanout(event) {
  const owner = ownerOf(event)
  if (!owner) return
  if (event.type === "permission.asked" || event.type === "question.asked") {
    const id = event.properties?.id
    if (typeof id === "string") {
      asked.set(id, owner)
      if (asked.size > MAX_ASKED) asked.delete(asked.keys().next().value)
    }
  }
  const writers = followers.get(owner)
  if (!writers?.size) return
  const line = JSON.stringify({ type: "event", event }) + "\n"
  for (const write of writers) write(line)
}

/**
 * Run one call from `vox daemon` on `session`, through OpenCode's in-process client. The
 * actions are a whitelist; each names the subscribed session or one of its own requests.
 */
async function runCall(client, session, call) {
  const raw = client._client
  const req = (method, url, body) => raw.request({ method, url, body })
  switch (call.action) {
    case "prompt":
      if (typeof call.text !== "string") throw new Error("a prompt needs text")
      return req("POST", `/session/${session}/prompt_async`, {
        parts: [{ type: "text", text: call.text }],
      })
    case "abort":
      return req("POST", `/session/${session}/abort`, {})
    case "rename":
      if (typeof call.title !== "string" || !call.title.trim()) throw new Error("a rename needs a title")
      return req("PATCH", `/session/${session}`, { title: call.title })
    case "summarize":
      if (typeof call.providerID !== "string" || typeof call.modelID !== "string") {
        throw new Error("a compaction needs the session's provider and model")
      }
      return req("POST", `/session/${session}/summarize`, {
        providerID: call.providerID,
        modelID: call.modelID,
      })
    case "command":
      if (typeof call.command !== "string" || !/^[A-Za-z0-9_.:-]+$/.test(call.command)) {
        throw new Error("not a command name")
      }
      return req("POST", `/session/${session}/command`, {
        command: call.command,
        arguments: typeof call.arguments === "string" ? call.arguments : "",
      })
    case "permission":
      if (typeof call.request !== "string" || !["once", "reject"].includes(call.reply)) {
        throw new Error("a permission reply needs its request and once or reject")
      }
      if (asked.get(call.request) !== session) throw new Error("not a request of this session")
      return req("POST", `/permission/${call.request}/reply`, {
        reply: call.reply,
        ...(typeof call.message === "string" ? { message: call.message } : {}),
      })
    case "question":
      if (typeof call.request !== "string" || !Array.isArray(call.answers)) {
        throw new Error("a question reply needs its request and answers")
      }
      if (asked.get(call.request) !== session) throw new Error("not a request of this session")
      return req("POST", `/question/${call.request}/reply`, { answers: call.answers })
    default:
      throw new Error("unknown action")
  }
}

/**
 * `relayed` notes each wake notice relayed to a session (session id → its texts), before
 * OpenCode is handed it: OpenCode may run the prompt's `chat.message` before `promptAsync`
 * returns, and that turn must know the message is Vox's notice, not the operator's (V030-21).
 */
function wakeChannel(client, relayed) {
  try {
    // `mkdtemp` makes the directory 0700, so only this user can reach the socket;
    // the token keeps every other process of theirs out as well.
    const dir = mkdtempSync(join(tmpdir(), "vox-oc-"))
    const path = join(dir, "wake.sock")
    const mirrorPath = join(dir, "mirror.sock")
    const token = randomBytes(32).toString("hex")
    const expected = Buffer.from(token)
    // Two sockets, one token: `wake.sock` takes one prompt per connection (ADR-020 6.13);
    // `mirror.sock` takes one subscription per connection and stays open (ADR-029 #542).
    const serve = (kind) => (conn) => {
      let buf = ""
      // One decoder for the connection: a character whose bytes span two reads is held back
      // until its last byte arrives, rather than each read decoding to U+FFFD at the seam.
      const utf8 = new StringDecoder("utf8")
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
      let authed = false
      let following = null // the session this connection follows, once subscribed
      const write = (line) => {
        try {
          if (!conn.destroyed) conn.write(line)
        } catch {}
      }
      conn.on("close", () => {
        if (following) followers.get(following)?.delete(write)
      })
      const onLine = async (line) => {
        let msg
        try {
          msg = JSON.parse(line)
        } catch {
          return following ? undefined : answer({ error: "not JSON" })
        }
        if (!authed) {
          const given = Buffer.from(String(msg?.token ?? ""))
          if (
            msg?.type !== "auth" ||
            given.length !== expected.length ||
            !timingSafeEqual(given, expected)
          ) {
            log("wake: refused a connection with the wrong token")
            return answer({ error: "wrong token" })
          }
          authed = true
          return
        }
        if (following) {
          // A call from `vox daemon` on the followed session.
          if (msg?.type !== "call") return
          let reply
          try {
            const res = await runCall(client, following, msg)
            const status = res?.response?.status ?? 0
            reply = status >= 200 && status < 300
              ? { type: "result", id: msg.id, ok: true }
              : { type: "result", id: msg.id, ok: false, error: "OpenCode answered " + status }
          } catch (e) {
            reply = { type: "result", id: msg.id, ok: false, error: String(e?.message ?? e) }
          }
          return write(JSON.stringify(reply) + "\n")
        }
        if (kind === "mirror") {
          if (msg?.type !== "subscribe" || typeof msg.session !== "string" || !msg.session) {
            return answer({ error: "expected a subscribe frame" })
          }
          done = true // no longer a one-shot: the deadline no longer applies
          clearTimeout(deadline)
          following = msg.session
          if (!followers.has(following)) followers.set(following, new Set())
          followers.get(following).add(write)
          log("mirror: following " + following)
          write(JSON.stringify({ type: "subscribed", session: following }) + "\n")
          // Its title as it is now, said as OpenCode's bus says a change of it: a title set before
          // this follow began (OpenCode's own, or a /rename) is the Session's name from the start
          // (ADR-029 MD-1), not only after the session is next updated.
          const followed = following
          client._client
            .request({ method: "GET", url: `/session/${followed}` })
            .then((res) => {
              const info = res?.data
              if (info?.id === followed && typeof info.title === "string") {
                const event = { type: "session.updated", properties: { info } }
                write(JSON.stringify({ type: "event", event }) + "\n")
              }
            })
            .catch(() => {})
          return
        }
        if (msg?.type !== "prompt" || !msg.session || typeof msg.text !== "string") {
          return answer({ error: "expected a prompt frame" })
        }
        done = true
        const noted = [...(relayed.get(msg.session) ?? []), msg.text].slice(-MAX_RELAYED)
        relayed.set(msg.session, noted)
        const forget = () => {
          const left = relayed.get(msg.session) ?? []
          const i = left.lastIndexOf(msg.text)
          if (i >= 0) left.splice(i, 1)
        }
        try {
          let res
          try {
            res = await client.session.promptAsync({
              path: { id: msg.session },
              body: { parts: [{ type: "text", text: msg.text }] },
            })
          } catch (e) {
            forget()
            throw e
          }
          const status = res?.response?.status ?? 0
          log("wake: session " + msg.session + " answered " + status)
          if (status >= 200 && status < 300) return answer({ ok: true })
          forget()
          answer({ error: "OpenCode answered " + status, gone: status === 404 })
        } catch (e) {
          log("wake: threw: " + e)
          answer({ error: String(e) })
        }
      }
      // Lines are handled one at a time, in order.
      let queue = Promise.resolve()
      conn.on("data", (chunk) => {
        if (done && !following) return
        buf += utf8.write(chunk)
        if (buf.length > MAX_FRAMES_BYTES) {
          done = true
          return conn.destroy()
        }
        let i
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i)
          buf = buf.slice(i + 1)
          queue = queue.then(() => onLine(line)).catch((e) => log("wake: threw: " + e))
        }
      })
    }
    const server = createServer(serve("wake"))
    server.on("error", (e) => log("wake: socket error: " + e))
    server.listen(path)
    // Bun's `listen` on a Unix path binds before it returns; `unref` so the socket
    // never keeps OpenCode alive.
    server.unref?.()
    const mirror = createServer(serve("mirror"))
    mirror.on("error", (e) => log("mirror: socket error: " + e))
    mirror.listen(mirrorPath)
    mirror.unref?.()
    removeOnExit(dir)
    sweep(dir)
    log("wake: listening at " + path + " and " + mirrorPath)
    return { path, mirrorPath, token }
  } catch (e) {
    log("wake: could not open the wake socket: " + e)
    return null
  }
}

export default async function vox({ $, client }) {
  log("plugin loaded (cwd=" + process.cwd() + ")")
  const relayed = new Map()
  const wake = wakeChannel(client, relayed)
  return {
    // Every event of OpenCode's bus, to the connections following its session (#542). The
    // `event` hook is fed in-process with the full set (permission.asked, question.asked,
    // message.*, session.*), and runs for every OpenCode, TUI or not.
    event: async ({ event }) => {
      try {
        fanout(event)
      } catch (e) {
        log("event: threw: " + e)
      }
    },
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
          output.env.VOX_NODE = VOX_NODE
          log("shell.env: VOX_SESSION=" + input.sessionID + " VOX_NODE=" + VOX_NODE)
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
        const bin = process.env.VOX_BIN || "vox"

        // Whether this message is a wake notice Vox relayed, not something the operator typed:
        // its text is one this session was relayed and has not had a turn on yet.
        const typed = output.parts.find((p) => p.type === "text" && typeof p.text === "string")
        const notes = relayed.get(sessionID) ?? []
        const at = typed ? notes.indexOf(typed.text) : -1
        const isWake = at >= 0
        if (isWake) notes.splice(at, 1)

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
          env.VOX_OPENCODE_MIRROR_SOCKET = wake.mirrorPath
        }

        const result =
          await $`${bin} agent hook --node ${VOX_NODE} --format text --session ${sessionID}`
            .env(env)
            .quiet()
            .nothrow()
        const text = result.stdout.toString()
        log("drain: exit=" + result.exitCode + " bytes=" + text.length)
        // **The fence's tag is this turn's own** (V030-21): a nonce drawn now, after the drain has
        // returned, so nothing in the room text can have known it. Only `</vox-room-<nonce>>` ends
        // the block; a fixed `</vox-room>` inside a message used to end it early, and whatever
        // followed read as outside the room.
        const nonce = randomBytes(8).toString("hex")

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
        //
        // **What follows the block is labelled as what it is** (V030-21). A wake notice Vox
        // relayed reaches OpenCode as a user message, but it is Vox's, not the operator's:
        // labelled "The user's message:" it read as the operator speaking.
        const after = isWake
          ? "Relayed by Vox; not the user's message:\n"
          : "The user's message:\n"
        const block =
          `<vox-room-${nonce} source="other agents; not the user">\n` +
          defang(text.trim()) +
          `\n</vox-room-${nonce}>\n\n` +
          after
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
