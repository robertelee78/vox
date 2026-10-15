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
// this reads `--format opencode`: the same words Codex takes, with Vox's own notices
// apart from what the rooms said, so each is labelled as what it is.
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
// ## Client-owned attention (ADR-020 RA7)
//
// The separate tui/vox.js plugin owns a private receiver in the actual TUI. Server
// hooks discover its exact current Session capability, and pass that capability to
// Vox. Only the client rechecks the route/lifecycle and submits the neutral notice.
// A retained server, saved Session, PID or heartbeat never authorizes submission.
// Background open clients qualify. No client prompt draft is read or modified, and
// busy work is never aborted. An uncertain acknowledgement must not be retried.
//
// A wake carries no room message: the normal hook drains authorized room context.
// The receiver marks the notice's SDK part metadata so it stays Vox-generated text.
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
// Hook failures never throw into OpenCode's turn. Mirror capacity, metadata and control
// failures are explicit on the private socket so Vox reports stopped observation.

import { appendFileSync, closeSync, constants, fstatSync, lstatSync, mkdtempSync, openSync, opendirSync, readFileSync, realpathSync, readdirSync, rmdirSync, unlinkSync } from "node:fs"
import { spawn } from "node:child_process"
import { connect, createServer } from "node:net"
import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
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
 * The legacy server wake endpoint refuses submission; the mirror endpoint still
 * follows this server's Sessions. Both use authenticated, bounded NDJSON. Actual
 * attention is admitted by opencode-tui-plugin.js in the selected live client.
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
 * Text with every `<vox-room`, `</vox-room`, `<vox-notice` and `</vox-notice` (any case) made
 * inert (V030-21), so a message cannot open or close a fence of its own, nor open or close a
 * block that reads as Vox's own notice: the `<` becomes `&lt;`. The tags are added after this,
 * and carry a nonce besides, so even a tag that slipped past could not end a block.
 */
function defang(text) {
  return text.replace(/<(\/?)(vox-(?:room|notice))/gi, "&lt;$1$2")
}

/**
 * What `vox agent hook --format opencode` printed: `vox`, Vox's own notices, and `room`, what
 * the rooms said. Output of any other shape is taken as room text, all of it, so it is fenced:
 * nothing reads as Vox's that Vox did not mark as its own.
 */
function drained(stdout) {
  try {
    const v = JSON.parse(stdout)
    if (v && typeof v.vox === "string" && typeof v.room === "string") return v
  } catch {}
  return { vox: "", room: stdout }
}

// The agent's own node, written in by `vox agent plugin opencode --node <name>` (ADR-020 2.1): the
// drain hook acts only as it, and every shell this session runs names it in `VOX_NODE`, so the
// agent's `vox room …` act as its node too, never as a person's node on the same machine.
const VOX_NODE = "@VOX_NODE@"

// **A headless run gets no Session** (ADR-029 SE-1): `opencode run` says so only in OpenCode's own
// argv, which this plugin, loaded inside OpenCode, reads. Measured on OpenCode 1.18.35
// (2026-10-10): `opencode run …` loads plugins with argv ["bun", "/$bunfs/root/src/index.js",
// "run", …]; the TUI loads them in its worker, ["bun", "/$bunfs/root/src/cli/tui/worker.js"]. The
// hook is told with VOX_OPENCODE_HEADLESS=1, as Claude Code tells it with its entrypoint.
const HEADLESS = process.argv.slice(2).find((a) => !String(a).startsWith("-")) === "run"

/**
 * The connections following a session's Session: session id → the set of `write` functions.
 * A sub-agent's session is followed through its parent (`parents`: child id → parent id).
 */
const followers = new Map()
const parents = new Map()
/** Requests OpenCode asked (permission or question id → the Session it was shown in). */
const asked = new Map()
const MAX_ASKED = 1024
const MAX_MIRROR_BYTES = 4 << 20
const MAX_MIRROR_EVENTS = 64
const MAX_MESSAGE_ROLES = 256
const MAX_PARENTS = 256
const MAX_SESSION_META = 64 << 10
const MAX_CONNECTIONS = 64
const MAX_CALLS = 32
const MAX_QUEUED_FRAMES = 64
const MAX_CONTROL_BYTES = 64 << 10
const CALL_WITHIN_MS = 30_000
let mirrorFailure = null

/** SDK transport with a deadline and bounded response, including non-success bodies. */
async function boundedJson(client, url, limit) {
  const controller = new AbortController()
  const deadline = setTimeout(() => controller.abort(), AUTH_IDLE_MS)
  deadline.unref?.()
  try {
    const transport = client._client.getConfig().fetch ?? globalThis.fetch
    const result = await client._client.request({ method: "GET", parseAs: "stream",
      responseStyle: "fields", signal: controller.signal, url,
      fetch: async (request) => {
        const response = await transport(request)
        if (!response.ok) {
          await response.body?.cancel()
          throw new Error("OpenCode metadata lookup answered " + response.status)
        }
        return response
      },
    })
    const reader = result?.data?.getReader?.()
    if (!reader) throw new Error("OpenCode did not stream its metadata lookup")
    const body = new Uint8Array(limit)
    let used = 0
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        if (value.byteLength > body.length - used) throw new Error("OpenCode metadata exceeds its byte bound")
        body.set(value, used)
        used += value.byteLength
      }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body.subarray(0, used)))
    } finally {
      await reader.cancel().catch(() => {})
      reader.releaseLock()
    }
  } finally { clearTimeout(deadline) }
}

function rememberParent(info) {
  if (typeof info?.id !== "string" || !info.id || info.id.length > 4096
    || (info.parentID != null && (typeof info.parentID !== "string" || !info.parentID || info.parentID.length > 4096))) {
    throw new Error("OpenCode supplied invalid session lineage")
  }
  // A root's null parent is authoritative too. Only memoized metadata is evicted.
  parents.delete(info.id)
  parents.set(info.id, info.parentID ?? null)
  if (parents.size > MAX_PARENTS) parents.delete(parents.keys().next().value)
}

async function ownerOf(client, event) {
  const p = event?.properties ?? {}
  let sid = p.sessionID ?? p.part?.sessionID ?? p.info?.sessionID ?? p.info?.id
  if (typeof sid !== "string") return null
  if ((event.type === "session.created" || event.type === "session.updated") && p.info?.id === sid) {
    rememberParent(p.info)
  }
  const seen = new Set()
  for (let depth = 0; depth < 32; depth += 1) {
    if (seen.has(sid)) throw new Error("OpenCode session lineage contains a cycle")
    seen.add(sid)
    if (!parents.has(sid)) {
      const info = await boundedJson(client, `/session/${encodeURIComponent(sid)}`, MAX_SESSION_META)
      if (info?.id !== sid) throw new Error("OpenCode could not resolve exact session lineage")
      rememberParent(info)
    }
    const parent = parents.get(sid)
    if (parent === null) return sid
    sid = parent
  }
  throw new Error("OpenCode session lineage exceeds 32 ancestors")
}

/** A bounded optimization only. A cache miss is resolved against OpenCode's own message. */
function mirrorEvents(client) {
  const messages = new Map()
  const queue = []
  let bytes = 0
  let count = 0
  let running = false
  const fail = (why) => {
    if (mirrorFailure) return
    mirrorFailure = String(why)
    log("mirror: stopped: " + mirrorFailure)
    const line = JSON.stringify({ type: "mirror-error", error: mirrorFailure }) + "\n"
    for (const writers of followers.values()) for (const write of writers) write(line)
  }
  const remember = (info) => {
    if (!info || typeof info.id !== "string" || typeof info.sessionID !== "string"
      || !["user", "assistant"].includes(info.role)) return null
    const value = { id: info.id, sessionID: info.sessionID, role: info.role }
    for (const field of ["agent", "providerID", "modelID"]) {
      if (typeof info[field] === "string") value[field] = info[field]
    }
    if (Buffer.byteLength(JSON.stringify(value)) > 4096) throw new Error("message metadata exceeds its bound")
    const key = JSON.stringify([value.sessionID, value.id])
    messages.delete(key)
    messages.set(key, value)
    if (messages.size > MAX_MESSAGE_ROLES) messages.delete(messages.keys().next().value)
    return value
  }
  const enrich = async (event) => {
    if (event.type === "message.updated") remember(event.properties?.info)
    if (event.type !== "message.part.updated") return event
    const part = event.properties?.part
    if (typeof part?.sessionID !== "string" || typeof part?.messageID !== "string") {
      throw new Error("a part has no authoritative message identity")
    }
    const key = JSON.stringify([part.sessionID, part.messageID])
    let info = messages.get(key)
    if (!info) {
      const candidate = (await boundedJson(client,
        `/session/${encodeURIComponent(part.sessionID)}/message/${encodeURIComponent(part.messageID)}`,
        MAX_MIRROR_BYTES))?.info
      if (candidate?.id !== part.messageID || candidate?.sessionID !== part.sessionID) {
        throw new Error("OpenCode could not resolve a part's message")
      }
      info = remember(candidate)
      if (!info) throw new Error("OpenCode supplied no user or assistant role for a part")
    }
    return { ...event, properties: { ...event.properties, voxMessage: info } }
  }
  const drain = async () => {
    if (running) return
    running = true
    try {
      while (queue.length) {
        const item = queue.shift()
        try {
          if (!mirrorFailure) {
            const raw = JSON.parse(item.line)
            const owner = await ownerOf(client, raw)
            // A title snapshot can wait behind a live rename's metadata lookup. Check
            // again here, not only when that snapshot's HTTP response first arrives.
            const writers = (item.targets ?? item.followers.get(owner) ?? [])
              .filter((write) => write.active && (!item.targets || !write.titleUpdated))
            if (owner && writers.length) {
              const event = await enrich(raw)
              if (Buffer.byteLength(JSON.stringify({ type: "event", event })) + 1 > MAX_MIRROR_BYTES) {
                throw new Error("an enriched mirror event exceeds its line bound")
              }
              if (!item.targets && event.type === "session.updated" && event.properties?.info?.id === owner) {
                for (const write of writers) write.titleUpdated = true
              }
              fanout(event, owner, writers)
            }
          }
        } catch (error) {
          fail(error?.message ?? error)
        } finally {
          bytes -= item.bytes
          count -= 1
          item.done()
        }
      }
    } finally {
      running = false
    }
  }
  return (event, targets = null) => {
    // Only events consumed by the Session adapter need lineage. In particular, an unused
    // deletion must not GET an already-deleted session and stop unrelated observations.
    if (!["message.updated", "message.part.updated", "session.updated", "session.idle",
      "permission.asked", "permission.replied", "question.asked", "question.replied",
      "question.rejected"].includes(event?.type)) return Promise.resolve()
    if (mirrorFailure) return Promise.resolve()
    if (!targets && !followers.size) return Promise.resolve()
    if (!targets && event.type === "session.updated") {
      const sid = event.properties?.info?.id
      // Exact subscribed id is already known; mark this before any asynchronous lineage
      // work, so an older in-flight snapshot cannot overwrite its live rename.
      for (const write of followers.get(sid) ?? []) write.titleUpdated = true
    }
    const line = JSON.stringify(event)
    const size = Buffer.byteLength(line)
    // Admission is synchronous. A concurrent hook cannot create an unbounded chain of
    // promises retaining bodies while one authoritative lookup is awaiting its response.
    if (count === MAX_MIRROR_EVENTS || size > MAX_MIRROR_BYTES - bytes) {
      fail("OpenCode events exceeded the bounded mirror queue; observation must restart")
      return Promise.resolve()
    }
    count += 1
    bytes += size
    return new Promise((done) => {
      // Capture recipients now. A later subscriber receives only the title snapshot, not
      // old part events that happened to be awaiting another session's metadata lookup.
      queue.push({ line, bytes: size, done, targets,
        followers: targets ? null : new Map([...followers].map(([id, writers]) => [id, [...writers]])) })
      void drain()
    })
  }
}

function fanout(event, owner, writers) {
  if (event.type === "permission.asked" || event.type === "question.asked") {
    const id = event.properties?.id
    if (typeof id !== "string" || !id || id.length > 4096) throw new Error("OpenCode request identity is missing or too long")
    if (asked.has(id) && asked.get(id) !== owner) throw new Error("OpenCode reused a pending request for another session")
    if (!asked.has(id) && asked.size >= MAX_ASKED) throw new Error("OpenCode has more than 1024 pending requests; observation must restart")
    asked.set(id, owner)
  } else if (["permission.replied", "question.replied", "question.rejected"].includes(event.type)) {
    const id = event.properties?.requestID
    if (asked.get(id) === owner) asked.delete(id)
  }
  const line = JSON.stringify({ type: "event", event }) + "\n"
  for (const write of writers) write(line)
}

/**
 * Run one call from `vox daemon` on `session`, through OpenCode's in-process client. The
 * actions are a whitelist; each names the subscribed session or one of its own requests.
 */
async function runCall(client, session, call) {
  const raw = client._client
  const req = async (method, url, body) => {
    const controller = new AbortController()
    const deadline = setTimeout(() => controller.abort(), CALL_WITHIN_MS)
    deadline.unref?.()
    try {
      const result = await raw.request({ method, url, body, signal: controller.signal,
        parseAs: "stream", responseStyle: "fields",
        fetch: async (request) => {
          const response = await (raw.getConfig().fetch ?? globalThis.fetch)(request)
          // Only status is needed. Neither success nor error response bodies are retained.
          await response.body?.cancel()
          return new Response(null, { status: response.status, statusText: response.statusText, headers: response.headers })
        },
      })
      return result
    } catch (error) {
      const uncertain = new Error(controller.signal.aborted
        ? "OpenCode control timed out; outcome unknown, do not assume it is safe to repeat"
        : "OpenCode control outcome unknown: " + String(error?.message ?? error))
      uncertain.outcomeUnknown = true
      throw uncertain
    } finally { clearTimeout(deadline) }
  }
  switch (call.action) {
    case "prompt":
      if (typeof call.text !== "string") throw new Error("a prompt needs text")
      return req("POST", `/session/${encodeURIComponent(session)}/prompt_async`, {
        parts: [{ type: "text", text: call.text }],
      })
    case "abort":
      return req("POST", `/session/${encodeURIComponent(session)}/abort`, {})
    case "rename":
      if (typeof call.title !== "string" || !call.title.trim()) throw new Error("a rename needs a title")
      return req("PATCH", `/session/${encodeURIComponent(session)}`, { title: call.title })
    case "summarize":
      if (typeof call.providerID !== "string" || typeof call.modelID !== "string") {
        throw new Error("a compaction needs the session's provider and model")
      }
      return req("POST", `/session/${encodeURIComponent(session)}/summarize`, {
        providerID: call.providerID,
        modelID: call.modelID,
      })
    case "command":
      if (typeof call.command !== "string" || !/^[A-Za-z0-9_.:-]+$/.test(call.command)) {
        throw new Error("not a command name")
      }
      return req("POST", `/session/${encodeURIComponent(session)}/command`, {
        command: call.command,
        arguments: typeof call.arguments === "string" ? call.arguments : "",
      })
    case "permission":
      if (typeof call.request !== "string" || !["once", "reject"].includes(call.reply)) {
        throw new Error("a permission reply needs its request and once or reject")
      }
      if (asked.get(call.request) !== session) throw new Error("not a request of this session")
      return req("POST", `/permission/${encodeURIComponent(call.request)}/reply`, {
        reply: call.reply,
        ...(typeof call.message === "string" ? { message: call.message } : {}),
      })
    case "question":
      if (typeof call.request !== "string" || !Array.isArray(call.answers)) {
        throw new Error("a question reply needs its request and answers")
      }
      if (asked.get(call.request) !== session) throw new Error("not a request of this session")
      return req("POST", `/question/${encodeURIComponent(call.request)}/reply`, { answers: call.answers })
    default:
      throw new Error("unknown action")
  }
}

// Discover only this node/directory's private TUI descriptors. A descriptor is not
// presence: the exact receiver must acknowledge its current route. Ambiguous or
// incomplete discovery is unavailable; it never submits anything or advances news.
async function attentionRoute(session, directory) {
  const found = []
  try {
    directory = realpathSync(directory)
    const scope = createHash("sha256").update(JSON.stringify([VOX_NODE, directory])).digest("hex")
    const registry = join("/tmp", "vox-oc-clients-" + scope.slice(0, 32))
    const st = lstatSync(registry)
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid?.() || (st.mode & 0o077)) return null
    const entries = opendirSync(registry)
    try {
      let entry, inspected = 0
      while ((entry = entries.readSync())) {
        if (++inspected > 64) return null
        if (!/^client-[A-Za-z0-9]{6}$/.test(entry.name)) continue
        const dir = join(registry, entry.name)
        const ds = lstatSync(dir)
        if (!ds.isDirectory() || ds.isSymbolicLink() || ds.uid !== st.uid || (ds.mode & 0o077)) return null
        let fd
        try {
          fd = openSync(join(dir, "client.json"), constants.O_RDONLY | constants.O_NOFOLLOW)
          const fs = fstatSync(fd)
          if (!fs.isFile() || fs.uid !== st.uid || (fs.mode & 0o077) || fs.size > 16384) return null
          const descriptor = JSON.parse(readFileSync(fd, "utf8"))
          if (descriptor.version !== 1 || descriptor.node !== VOX_NODE || descriptor.directory !== directory
            || descriptor.socket !== join(dir, "attention.sock") || !/^[0-9a-f]{64}$/.test(descriptor.token)
            || !/^[0-9a-f]{64}$/.test(descriptor.client)) return null
          const ss = lstatSync(descriptor.socket)
          if (!ss.isSocket() || ss.uid !== st.uid) return null
          found.push(descriptor)
        } catch (e) {
          if (e?.code !== "ENOENT") return null
        } finally { if (fd !== undefined) closeSync(fd) }
      }
    } finally { entries.closeSync() }
    const answers = await Promise.all(found.map((descriptor) => new Promise((resolve) => {
      const conn = connect(descriptor.socket)
      let settled = false, buffer = "", bytes = 0
      const decoder = new StringDecoder("utf8")
      const finish = (value) => { if (settled) return; settled = true; clearTimeout(timer); conn.destroy(); resolve(value) }
      const timer = setTimeout(() => finish({ incomplete: true }), AUTH_IDLE_MS)
      timer.unref?.()
      conn.on("error", (e) => finish(e?.code === "ECONNREFUSED" || e?.code === "ENOENT" ? null : { incomplete: true }))
      conn.on("close", () => finish({ incomplete: true }))
      conn.on("connect", () => conn.write(JSON.stringify({ type: "auth", token: descriptor.token }) + "\n"
        + JSON.stringify({ type: "route", session }) + "\n"))
      conn.on("data", (chunk) => {
        bytes += chunk.length
        if (bytes > 16384) return finish({ incomplete: true })
        buffer += decoder.write(chunk)
        const end = buffer.indexOf("\n")
        if (end < 0) return
        try {
          const response = JSON.parse(buffer.slice(0, end))
          if (response.outcome === "unavailable") return finish(null)
          if (response.outcome !== "available" || response.session !== session || response.client !== descriptor.client
            || !/^[0-9a-f]{64}$/.test(response.route)) return finish({ incomplete: true })
          finish({ ...descriptor, route: response.route })
        } catch { finish({ incomplete: true }) }
      })
    })))
    if (answers.some((a) => a?.incomplete)) return null
    const eligible = answers.filter(Boolean)
    return eligible.length === 1 ? eligible[0] : null
  } catch (e) { log("attention discovery unavailable: " + e); return null }
}

// Existing server socket remains the Session mirror; it cannot admit client attention.
function wakeChannel(client, mirrorEvent) {
  try {
    // `mkdtemp` makes the directory 0700, so only this user can reach the socket;
    // the token keeps every other process of theirs out as well.
    const dir = mkdtempSync(join(tmpdir(), "vox-oc-"))
    const path = join(dir, "wake.sock")
    const mirrorPath = join(dir, "mirror.sock")
    const token = randomBytes(32).toString("hex")
    const expected = Buffer.from(token)
    // Two sockets, one token: `wake.sock` refuses obsolete server-only wake requests;
    // `mirror.sock` takes one subscription per connection and stays open (ADR-029 #542).
    let connections = 0
    // Includes queued work of closed sockets until its awaited operation completes.
    let queuedTotal = 0
    let queuedTotalBytes = 0
    let snapshots = 0
    const serve = (kind) => (conn) => {
      conn.on("error", () => {})
      if (connections >= MAX_CONNECTIONS) {
        conn.end(JSON.stringify({ type: "mirror-error", error: "OpenCode has 64 active Vox socket connections; connection refused" }) + "\n")
        return
      }
      connections += 1
      conn.once("close", () => { connections -= 1 })
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
          if (conn.destroyed || conn.writableEnded) return
          if (conn.writableLength + Buffer.byteLength(line) > MAX_MIRROR_BYTES) {
            conn.end(JSON.stringify({ type: "mirror-error", error:
              "the mirror reader could not keep up; observation must restart" }) + "\n")
            return
          }
          conn.write(line)
        } catch {}
      }
      write.active = true
      conn.on("close", () => {
        write.active = false
        if (following) {
          const writers = followers.get(following)
          writers?.delete(write)
          if (writers?.size === 0) {
            followers.delete(following)
            for (const [id, owner] of asked) if (owner === following) asked.delete(id)
          }
        }
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
          if (!Number.isSafeInteger(msg.id) || msg.id < 1 || Buffer.byteLength(line) > MAX_CONTROL_BYTES) {
            return write(JSON.stringify({ type: "result", id: msg.id, ok: false, error: "control identity or 64 KiB byte bound refused; nothing was sent" }) + "\n")
          }
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
          // A queued subscribe is not admitted after its close callback has already run.
          if (!write.active) return
          if (msg?.type !== "subscribe" || typeof msg.session !== "string" || !msg.session || msg.session.length > 4096) {
            return answer({ error: "expected a subscribe frame" })
          }
          done = true // no longer a one-shot: the deadline no longer applies
          clearTimeout(deadline)
          following = msg.session
          if (!followers.has(following)) followers.set(following, new Set())
          followers.get(following).add(write)
          log("mirror: following " + following)
          write(JSON.stringify({ type: "subscribed", session: following }) + "\n")
          if (mirrorFailure) {
            write(JSON.stringify({ type: "mirror-error", error: mirrorFailure }) + "\n")
            return
          }
          // Its title as it is now, said as OpenCode's bus says a change of it: a title set before
          // this follow began (OpenCode's own, or a /rename) is the Session's name from the start
          // (ADR-029 MD-1), not only after the session is next updated.
          const followed = following
          if (snapshots >= MAX_CONNECTIONS) {
            write(JSON.stringify({ type: "mirror-error", error: "OpenCode session snapshot queue is full; observation stopped" }) + "\n")
            return
          }
          snapshots += 1
          boundedJson(client, `/session/${encodeURIComponent(followed)}`, MAX_SESSION_META)
            .then((info) => {
              if (info?.id === followed && typeof info.title === "string" && !write.titleUpdated) {
                const event = { type: "session.updated", properties: { info } }
                void mirrorEvent(event, [write])
              }
            })
            .catch((error) => write(JSON.stringify({ type: "mirror-error", error: "session snapshot unavailable: " + String(error?.message ?? error) }) + "\n"))
            .finally(() => { snapshots -= 1 })
          return
        }
        // A retained server is not an attached client. Old wake registrations must
        // fail honestly; only the separate TUI receiver may admit attention.
        return answer({ error: "Vox attention requires an open, registered OpenCode TUI Session", gone: true })
      }
      // Lines are handled one at a time, in order.
      let queue = Promise.resolve()
      let queued = 0
      let queuedBytes = 0
      let refused = false
      conn.on("data", (chunk) => {
        if (refused) return
        if (done && !following) return
        buf += utf8.write(chunk)
        if (Buffer.byteLength(buf) > MAX_FRAMES_BYTES) {
          refused = true
          return answer({ type: "mirror-error", error: "Vox socket input exceeds 1 MiB; observation stopped" })
        }
        let i
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i)
          buf = buf.slice(i + 1)
          const size = Buffer.byteLength(line)
          if (queued >= MAX_CALLS || size > MAX_FRAMES_BYTES - queuedBytes
            || queuedTotal >= MAX_QUEUED_FRAMES || size > MAX_MIRROR_BYTES - queuedTotalBytes) {
            refused = true
            buf = ""
            // Accepted queued calls keep their order; do not cancel or replay them. The final
            // failure follows their results, so the reader knows this observation stopped.
            queue = queue.finally(() => answer({ type: "mirror-error", error:
              "Vox socket queue exceeded its per-connection (32 frames/1 MiB) or shared (64 frames/4 MiB) bound; observation stopped, excess frames were not executed" }))
            return
          }
          queued += 1
          queuedBytes += size
          queuedTotal += 1
          queuedTotalBytes += size
          queue = queue.then(() => onLine(line)).catch((e) => log("wake: threw: " + e))
            .finally(() => { queued -= 1; queuedBytes -= size; queuedTotal -= 1; queuedTotalBytes -= size })
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

export default async function vox({ $, client, directory }) {
  log("plugin loaded (cwd=" + process.cwd() + ")")
  const mirrorEvent = mirrorEvents(client)
  const wake = wakeChannel(client, mirrorEvent)
  return {
    // Every event of OpenCode's bus, to the connections following its session (#542). The
    // `event` hook is fed in-process with the full set (permission.asked, question.asked,
    // message.*, session.*), and runs for every OpenCode, TUI or not.
    event: async ({ event }) => {
      try {
        await mirrorEvent(event)
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
          // shell.env is merged over the server's inherited environment. Empty
          // overrides remove a parent harness's identity from this tool's sender
          // selection; deleting output keys would leave the inherited IDs intact.
          output.env.CODEX_THREAD_ID = ""
          output.env.CLAUDE_CODE_SESSION_ID = ""
          output.env.VOX_SESSION = input.sessionID
          output.env.VOX_HARNESS = "opencode"
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
        const origin = typed?.metadata?.vox_attention
        // This SDK part metadata is supplied by our actual TUI receiver. Room text
        // and operator typing cannot synthesize a part's metadata. It labels source;
        // it grants no room/drive permission and is not an admission credential.
        const isWake = typed?.synthetic === true && origin?.source === "vox"
          && /^[0-9a-f]{64}$/.test(origin.client ?? "")
          && /^[0-9a-f]{64}$/.test(origin.route ?? "") && /^[0-9a-f]{32}$/.test(origin.id ?? "")

        // `.quiet()` keeps the child's output out of OpenCode's, `.nothrow()`
        // makes a non-zero exit a value rather than an exception — `vox agent
        // hook` always exits 0, but a missing binary would otherwise throw.
        //
        // The wake channel goes to the hook alone, in its environment: the hook
        // registers it, so `vox daemon` can interrupt this session (see above).
        const env = { ...process.env, VOX_SESSION: sessionID, VOX_HARNESS: "opencode" }
        // This hook belongs to the actual OpenCode Session, even when its server
        // was started by another harness. Neither that parent's ID nor socket is ours.
        for (const key of ["CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
          "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN"]) delete env[key]
        if (HEADLESS) env.VOX_OPENCODE_HEADLESS = "1"
        delete env.VOX_OPENCODE_ATTENTION_SOCKET
        delete env.VOX_OPENCODE_ATTENTION_TOKEN
        delete env.VOX_OPENCODE_ATTENTION_ROUTE
        const attention = HEADLESS ? null : await attentionRoute(sessionID, directory ?? process.cwd())
        if (attention) {
          env.VOX_OPENCODE_ATTENTION_SOCKET = attention.socket
          env.VOX_OPENCODE_ATTENTION_TOKEN = attention.token
          env.VOX_OPENCODE_ATTENTION_ROUTE = attention.route
        }
        if (wake) {
          env.VOX_OPENCODE_WAKE_SOCKET = wake.path
          env.VOX_OPENCODE_WAKE_TOKEN = wake.token
          env.VOX_OPENCODE_MIRROR_SOCKET = wake.mirrorPath
        }

        const result =
          await $`${bin} agent hook --node ${VOX_NODE} --format opencode --session ${sessionID}`
            .env(env)
            .quiet()
            .nothrow()
        const out = drained(result.stdout.toString())
        log("drain: exit=" + result.exitCode + " vox=" + out.vox.length + " room=" + out.room.length)
        // **The fence's tag is this turn's own** (V030-21): a nonce drawn now, after the drain has
        // returned, so nothing in the room text can have known it. Only `</vox-room-<nonce>>` ends
        // the block; a fixed `</vox-room>` inside a message used to end it early, and whatever
        // followed read as outside the room.
        const nonce = randomBytes(8).toString("hex")

        // A quiet room injects nothing at all — not "no new messages". A quiet
        // room should cost zero tokens per turn.
        if (!out.vox.trim() && !out.room.trim()) {
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
        //
        // **Vox's own notices are labelled as Vox's, outside the fence** (the RB-5 ask, a node
        // that is not working): they are not other agents' words, and inside the fence they read
        // as such. Their block's tag carries this turn's nonce too, and no room text can open or
        // close one (`defang`), so nothing a member posts reads as Vox's notice.
        const notice = out.vox.trim()
          ? `<vox-notice-${nonce} source="Vox itself; not the user, not other agents">\n` +
            defang(out.vox.trim()) +
            `\n</vox-notice-${nonce}>\n\n`
          : ""
        const room = out.room.trim()
          ? `<vox-room-${nonce} source="other agents; not the user">\n` +
            defang(out.room.trim()) +
            `\n</vox-room-${nonce}>\n\n`
          : ""
        const block = notice + room + after
        for (const part of output.parts) {
          if (part.type === "text" && typeof part.text === "string") {
            part.text = block + part.text
            log("chat.message: injected " + block.length + " chars")
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
