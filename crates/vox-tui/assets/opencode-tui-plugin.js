// Vox OpenCode TUI attention receiver. Installed by vox setup into tui/vox.js.
// This module runs in the actual client, not the retained OpenCode server.
import { createRoot, createComputed } from "solid-js"
import { createServer } from "node:net"
import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs"
import { spawn } from "node:child_process"
import { join } from "node:path"
import { StringDecoder } from "node:string_decoder"

const VOX_NODE = "@VOX_NODE@"
const MAX_FRAME = 64 << 10
const MAX_CONNECTIONS = 8
const MAX_RECEIPTS = 128
const AUTH_WITHIN_MS = 5000
const REQUEST_WITHIN_MS = 30000

export const id = "vox-attention"
export async function tui(api) {
  if (api.lifecycle.signal.aborted) return
  const directory = realpathSync(api.state.path.directory)
  const scope = createHash("sha256").update(JSON.stringify([VOX_NODE, directory])).digest("hex")
  const registry = join("/tmp", "vox-oc-clients-" + scope.slice(0, 32))
  try { mkdirSync(registry, { mode: 0o700 }) } catch (e) { if (e.code !== "EEXIST") throw e }
  const stat = lstatSync(registry)
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077)) {
    throw new Error("Vox client registry is not an owned private directory")
  }
  const dir = mkdtempSync(join(registry, "client-"))
  const socket = join(dir, "attention.sock")
  const token = randomBytes(32).toString("hex")
  const client = randomBytes(32).toString("hex")
  const expected = Buffer.from(token)
  const sockets = new Set()
  let stopped = false
  let session = null
  let route = randomBytes(32).toString("hex")
  let receipts = new Map()
  let inFlight = false
  let disposeRoute = () => {}
  let helper
  let listening = false
  let registration = null
  let wanted = null
  const live = () => !stopped && !api.lifecycle.signal.aborted
  const currentSession = () => {
    const current = api.route.current
    const value = current.name === "session" ? current.params?.sessionID : null
    return typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= 4096 ? value : null
  }
  const register = () => {
    if (!listening || registration || !wanted || !live()) return
    const next = wanted
    wanted = null
    if (session !== next.session || route !== next.route || currentSession() !== next.session) return
    // Registration does not drain any context or start a turn. A reopened idle TUI
    // therefore becomes reachable without borrowing server lifetime or user input.
    const env = { ...process.env, VOX_SESSION: next.session, VOX_HARNESS: "opencode", VOX_OPENCODE_ATTENTION_SOCKET: socket,
      VOX_OPENCODE_ATTENTION_TOKEN: token, VOX_OPENCODE_ATTENTION_ROUTE: next.route }
    for (const key of ["CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
      "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN"]) delete env[key]
    let child
    try {
      child = spawn(process.env.VOX_BIN || "vox", ["agent", "hook", "--node", VOX_NODE,
        "--session", next.session, "--attention-register"],
        { cwd: directory, env, stdio: ["ignore", "ignore", "ignore"] })
    } catch { return }
    registration = child
    const deadline = setTimeout(() => child.kill("SIGKILL"), REQUEST_WITHIN_MS)
    deadline.unref?.()
    let ended = false
    const finish = () => {
      if (ended) return
      ended = true
      clearTimeout(deadline)
      if (registration === child) registration = null
      // At most one coalesced newer activation follows. A failed activation is
      // never retried on a timer; its old result cannot make a new route current.
      if (live()) register()
    }
    child.once("error", finish)
    child.once("exit", finish)
  }
  // OpenCode's supported Solid runtime supplies the same reactive route getter used by
  // its UI. Computed runs synchronously on route changes, including A -> B -> A.
  createRoot((dispose) => {
    disposeRoute = dispose
    createComputed(() => {
      const next = currentSession()
      if (next === session) return
      session = next
      route = randomBytes(32).toString("hex")
      receipts = new Map()
      wanted = session ? { session, route } : null
      register()
    })
  })
  const server = createServer((conn) => {
    conn.on("error", () => {})
    if (!live() || sockets.size >= MAX_CONNECTIONS) { conn.destroy(); return }
    sockets.add(conn)
    let buffer = ""
    let bytes = 0
    let authed = false
    let handled = false
    const decoder = new StringDecoder("utf8")
    const deadline = setTimeout(() => conn.destroy(), AUTH_WITHIN_MS)
    deadline.unref?.()
    const reply = (value) => {
      handled = true
      if (!conn.destroyed && !conn.writableEnded) conn.end(JSON.stringify(value) + "\n")
    }
    conn.once("close", () => { sockets.delete(conn); clearTimeout(deadline) })
    const receive = (msg) => {
      if (handled) return
      if (!authed) {
        const given = Buffer.from(typeof msg?.token === "string" ? msg.token : "")
        if (msg?.type !== "auth" || given.length !== expected.length || !timingSafeEqual(given, expected)) {
          handled = true; conn.destroy(); return
        }
        authed = true
        return
      }
      if (msg?.type === "route") {
        if (!live() || !session || msg.session !== session || currentSession() !== session) {
          return reply({ outcome: "unavailable" })
        }
        // Retire a full receipt generation only at fresh registration. Old capabilities
        // then refuse; receipt eviction can never cause a duplicate submission.
        if (receipts.size >= MAX_RECEIPTS && !inFlight) {
          route = randomBytes(32).toString("hex")
          receipts = new Map()
          wanted = { session, route }
          register()
        }
        return reply({ outcome: "available", session, client, route })
      }
      const validID = typeof msg?.id === "string" && /^[0-9a-f]{32}$/.test(msg.id)
      const answer = (outcome, error) => reply({ id: validID ? msg.id : null, outcome, ...(error ? { error } : {}) })
      if (msg?.type !== "attention" || !validID || typeof msg.text !== "string" || !msg.text.trim()
        || Buffer.byteLength(msg.text) > MAX_FRAME / 2) return answer("rejected", "invalid attention frame")
      if (!live() || !session || msg.session !== session || msg.route !== route || currentSession() !== session) {
        return answer("unavailable", "the exact client Session route is no longer open")
      }
      const digest = createHash("sha256").update(msg.text).digest("hex")
      const previous = receipts.get(msg.id)
      if (previous) {
        if (previous.digest !== digest) return answer("rejected", "attention ID was already used with different text")
        return answer(previous.outcome, previous.error)
      }
      if (inFlight || receipts.size >= MAX_RECEIPTS) return answer("unavailable", "client attention capacity is full")
      handled = true
      clearTimeout(deadline)
      inFlight = true
      const record = { digest, outcome: "unknown" }
      receipts.set(msg.id, record)
      const controller = new AbortController()
      const limit = setTimeout(() => controller.abort(), REQUEST_WITHIN_MS)
      limit.unref?.()
      // No await separates the final live route check above from this client-owned
      // submission. Never touch PromptRef or abort busy work. Admission before close
      // is allowed to complete; close/lost ACK never authorizes a replay.
      let request
      try {
        request = api.client.session.promptAsync({ sessionID: session, directory,
          parts: [{ type: "text", text: "Vox-generated attention notice; not the operator's message:\n" + msg.text, synthetic: true,
            metadata: { vox_attention: { source: "vox", client, route, id: msg.id } } }],
        }, { signal: controller.signal, responseStyle: "fields" })
      } catch (error) { request = Promise.reject(error) }
      Promise.resolve(request).then((result) => {
        const status = result?.response?.status ?? 0
        record.outcome = status >= 200 && status < 300 ? "accepted" : "unknown"
        if (record.outcome === "unknown") record.error = "OpenCode did not acknowledge acceptance; do not retry"
      }, () => {
        record.outcome = "unknown"
        record.error = "OpenCode acceptance is unknown; do not retry"
      }).finally(() => {
        clearTimeout(limit)
        inFlight = false
        answer(record.outcome, record.error)
      })
    }
    conn.on("data", (chunk) => {
      if (handled) return
      bytes += chunk.length
      if (bytes > MAX_FRAME) { handled = true; conn.destroy(); return }
      buffer += decoder.write(chunk)
      let end
      while (!handled && (end = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1)
        try { receive(JSON.parse(line)) } catch { handled = true; conn.destroy() }
      }
    })
  })
  const dispose = () => {
    if (stopped) return
    stopped = true
    session = null
    route = randomBytes(32).toString("hex")
    receipts.clear()
    wanted = null
    registration?.kill("SIGKILL")
    disposeRoute()
    try { server.close() } catch {}
    for (const conn of sockets) conn.destroy()
    helper?.stdin?.end()
    for (const path of [join(dir, "client.json"), socket]) { try { unlinkSync(path) } catch {} }
    try { rmdirSync(dir) } catch {}
    try { rmdirSync(registry) } catch {}
  }
  api.lifecycle.signal.addEventListener("abort", dispose, { once: true })
  api.lifecycle.onDispose(dispose)
  server.on("error", dispose)
  server.listen(socket, () => {
    if (!live()) { dispose(); return }
    try {
      writeFileSync(join(dir, "client.json"), JSON.stringify({ version: 1, node: VOX_NODE, directory, socket, token, client }), { mode: 0o600, flag: "wx" })
      listening = true
      register()
    } catch { dispose() }
  })
  server.unref?.()
  // Kernel pipe close also removes the exact owned descriptor/socket after abrupt exit.
  helper = spawn("/bin/sh", ["-c", 'read _; rm -f -- "$1/client.json" "$1/attention.sock"; rmdir -- "$1"; rmdir -- "$2" 2>/dev/null', "vox-oc-client-cleanup", dir, registry],
    { detached: true, stdio: ["pipe", "ignore", "ignore"] })
  helper.on("error", () => {})
  helper.unref()
}
