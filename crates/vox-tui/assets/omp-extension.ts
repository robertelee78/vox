// vox — Oh My Pi native extension (ADR-029).
// The session owns this capability. The daemon cannot select a different session through it.
import { createServer } from "node:net"
import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { mkdtempSync, chmodSync, unlinkSync, rmdirSync } from "node:fs"
import { spawn } from "node:child_process"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { StringDecoder } from "node:string_decoder"

const VOX_NODE = "@VOX_NODE@"
const MAX_FRAME = 64 << 10
const MAX_OUTPUT = 4 << 20
const MAX_CONNECTIONS = 8
const REQUEST_WITHIN_MS = 30000
const MAX_NOTICES = 128
const WAKE_TYPE = "vox-neutral-wake"
const WAKE_PREFIX = "vox-wake:"
const CONTEXT_STAGED = "vox-context-staged"
const CONTEXT_ACCEPTED = "vox-context-accepted"


export default function vox(pi) {
  let ctx = null, session = null, route = randomBytes(32).toString("hex")
  let generation = 0, listening = false, stopped = false, registration = null
  let lastName = null, confirmed = false, refusal = null, readyNode = false
  let watcher = null, instance = null, generationRef = null, watcherReady = null, watcherFailed = false
  let ownership = Promise.resolve(), retryTimer = null, retryStep = 0, mismatchEpisode = false
  let commandId = 0, commands = new Map(), reconciliationTimer = null, installPending = null
  let availabilityEpoch = 0, successorPending = false
  const token = randomBytes(32).toString("hex")
  const expected = Buffer.from(token)
  const notices = new Map(), materializations = new Map()
  let operation = null, providerActive = 0, poisoned = false, ordinarySensitive = false, transitionFence = null

  const dir = mkdtempSync(join(tmpdir(), "vox-omp-"))
  chmodSync(dir, 0o700)
  const socketPath = join(dir, "bridge.sock")
  // The kernel closes this pipe even after SIGKILL. The helper removes only this owned socket
  // and its empty private directory; it does not launch a harness or handle room content.
  try {
    const cleanup = spawn("/bin/sh", ["-c", "read _; rm -f -- \"$1/bridge.sock\"; rmdir -- \"$1\"", "vox-omp-cleanup", dir],
      { detached: true, stdio: ["pipe", "ignore", "ignore"] })
    cleanup.on("error", () => {})
    cleanup.unref()
  } catch {}
  const sockets = new Set(), followers = new Set(), children = new Set(), tools = new Map()
  // OMP provides PI_SESSION_ID in its tool environment. Node identity is shared by this
  // installed extension, not inferred from a parent harness's environment.
  process.env.VOX_NODE = VOX_NODE
  const current = () => !stopped && ctx?.mode === "tui" && ctx?.agent.kind === "main"
    && ctx?.sessionManager.getSessionId() === session && !!session
    && (!transitionFence || branchMatches(ctx.sessionManager, transitionFence))
  const env = () => {
    const e = { ...process.env, VOX_NODE, VOX_HARNESS: "omp", VOX_SESSION: session,
      VOX_OPENCODE_WAKE_SOCKET: socketPath, VOX_OPENCODE_WAKE_TOKEN: token,
      VOX_OPENCODE_MIRROR_SOCKET: socketPath, VOX_OPENCODE_ATTENTION_SOCKET: socketPath,
      VOX_OPENCODE_ATTENTION_TOKEN: token, VOX_OPENCODE_ATTENTION_ROUTE: route,
      VOX_OMP_INSTANCE: instance || "", VOX_OMP_GENERATION: generationRef || "" }
    for (const k of ["CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
      "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN", "OPENCODE_SESSION_ID", "VOX_OPENCODE_HEADLESS"]) delete e[k]
    return e
  }
  function branchMatches(manager, stamp) {
    const branch = manager.getBranch()
    const anchor = stamp.leaf === null ? -1 : branch.findIndex(entry => entry.id === stamp.leaf)
    return (stamp.leaf === null || anchor !== -1)
      && !branch.slice(anchor + 1).some(entry => stamp.existing.has(entry.id))
  }
  function resetBoundary(branch) {
    for (let index = branch.length - 1; index >= 0; index--) {
      if (branch[index].type === "reset_boundary") return branch[index].id
    }
    return null
  }
  function fence() {
    const manager = ctx?.sessionManager
    if (!current() || !manager) return null
    const leaf = manager.getLeafId()
    return { session, generation, leaf, reset: resetBoundary(manager.getBranch()) }
  }
  function fenced(f, branch = null) {
    if (!f || !current() || session !== f.session || generation !== f.generation) return false
    branch ??= ctx.sessionManager.getBranch()
    return resetBoundary(branch) === f.reset
      && (f.leaf === null || branch.some(entry => entry.id === f.leaf))
  }
  function neutral(record) {
    pi.sendMessage({ customType: WAKE_TYPE, content: WAKE_PREFIX + record.id,
      display: false, attribution: "agent" }, { deliverAs: "aside" })
  }
  function retireNotice(record) {
    if (record.state === "cancelled" && record.source === "drive") {
      send({ type: "discard", id: record.id })
    }
    notices.delete(record.id)
  }
  function reconcileQueued() {
    if (!current()) return
    const branch = ctx.sessionManager.getBranch()
    for (const record of notices.values()) {
      if (record.state === "committed" || record.state === "cancelled") {
        retireNotice(record)
        continue
      }
      if (record.state !== "queued") continue
      const isWake = entry => entry.type === "custom_message"
        && entry.customType === WAKE_TYPE && entry.content === WAKE_PREFIX + record.id
      const wake = branch.find(isWake)
      // Absence alone is not a discard: sendMessage may still be normalizing or
      // waiting in OMP's native aside queue. A reset, lost ancestry, or a wake
      // known to have left the active branch is a definitive boundary.
      if (!fenced(record.fence, branch) || (!wake
        && (record.entry || ctx.sessionManager.getEntries().some(isWake)))) record.state = "cancelled"
      else if (wake) record.entry = wake.id
      // Accepted history is reconstructed from native entries, not this live queue.
      if (record.state === "committed" || record.state === "cancelled") retireNotice(record)
    }
  }
  function queueBusy() {
    reconcileQueued()
    return [...notices.values()].some(record =>
      record.state === "queued" || record.state === "preparing" || record.state === "dispatched")
  }
  function admissionAvailable() {
    if (operation) return false
    let retained = 0
    for (const record of notices.values()) {
      if (record.state === "committed" || record.state === "cancelled") continue
      if (record.state === "queued" || record.state === "preparing" || record.state === "dispatched") return false
      retained++
    }
    return retained < MAX_NOTICES
  }
  function queue(id, source, text) {
    if (queueBusy() || notices.has(id) || notices.size >= MAX_NOTICES || operation || !current() || !generationRef || !readyNode) return false
    const stamp = fence()
    if (!stamp) return false
    const record = { id, source, text, fence: stamp, state: "queued" }
    notices.set(id, record)
    try { neutral(record) } catch { record.state = "unknown" }
    return true
  }
  function finish(op, command) {
    if (!op || op.done) return
    op.done = true
    op.decision = command
    if (op.record) {
      const pending = materializations.get(op.record.id)
      if (pending) {
        materializations.delete(op.record.id)
        pending.reject(new Error("The exact OMP Session route changed"))
      }
    }
    if (op.child && !op.child.stdin.destroyed) {
      if (command) op.child.stdin.end(command + "\n")
      else op.child.stdin.end()
    }
    if (op.record) op.record.state = command === "commit" ? (op.child ? "committing" : "committed") : command === "cancel" ? "cancelled" : "unknown"
    if (!command) poisoned = true
    // Keep ownership until the hook confirms either decision and exits.
    if (!op.child && operation === op) operation = null
  }
  function observeOrdinary() {
    const op = operation
    if (op?.ordinary && op.observed && fenced(op.fence)
      && ctx.sessionManager.getBranch().some(entry => entry.type === "custom_message"
        && entry.customType === "vox-ordinary-context" && entry.content === op.content)) {
      ordinarySensitive = true
      finish(op, "commit")
    }
  }
  function materialize(id) {
    const socket = [...followers].find(follower => !follower.destroyed)
    if (!socket || materializations.has(id)) return Promise.reject(new Error("The authorized Drive connection is unavailable"))
    const { promise, resolve, reject } = Promise.withResolvers()
    materializations.set(id, { socket, resolve, reject })
    socket.write(JSON.stringify({ type: "materialize", id }) + "\n", error => {
      if (error && materializations.get(id)?.socket === socket) {
        materializations.delete(id)
        reject(error)
      }
    })
    return promise
  }
  function prepare(op) {
    const { promise, resolve, reject } = Promise.withResolvers()
    let child
    const e = env()
    if (op.record?.source === "attention") {
      e.VOX_OMP_NOTICE = op.record.text + "\nNotice reference: " + Buffer.from(op.record.id, "hex").toString("base64url")
    }
    else delete e.VOX_OMP_NOTICE
    try {
      child = spawn(process.env.VOX_BIN || "vox",
        ["agent", "hook", "--node", VOX_NODE, "--session", op.fence.session, "--format", "opencode", "--omp-prepare"],
        { cwd: ctx.cwd, env: e, stdio: ["pipe", "pipe", "pipe"] })
    } catch (error) { reject(error); return promise }
    op.child = child
    const closed = Promise.withResolvers()
    op.closed = closed.promise
    child.stdin.on("error", () => {})
    let stderrSize = 0
    child.stderr.on("data", chunk => { stderrSize += chunk.length; if (stderrSize > MAX_OUTPUT) child.kill() })
    const deadline = setTimeout(() => child.kill(), REQUEST_WITHIN_MS)
    deadline.unref?.()
    let buffer = Buffer.alloc(0), settled = false, enveloped = false
    const fail = error => { if (!settled) { settled = true; reject(error); child.kill() } }
    child.once("error", fail)
    child.once("close", code => {
      clearTimeout(deadline)
      if (!enveloped && fenced(op.fence)) {
        confirmed = false
        report(code === 75 ? "Session registration is no longer present; reacquiring it" : "context preparation unavailable; reacquiring registration")
        scheduleRetry()
      }
      if (!settled) fail(new Error("Vox prepare ended before its envelope"))
      if (op.decision === "commit" || op.decision === "cancel") {
        const confirmed = enveloped && code === 0
        if (op.record) op.record.state = confirmed ? (op.decision === "commit" ? "committed" : "cancelled") : "unknown"
        if (!confirmed && enveloped) {
          poisoned = true
          publish({ type: "unavailable", error: "Vox context " + op.decision + " was not confirmed" })
        }
      } else if (!op.done) {
        if (!enveloped) {
          confirmed = false
          op.done = true
          if (op.record) op.record.state = "cancelled"
        } else finish(op, null)
      }
      if (operation === op) operation = null
      closed.resolve()
    })
    child.stdout.on("data", chunk => {
      if (settled) return
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length > MAX_OUTPUT) { fail(new Error("Vox prepare envelope exceeds its bound")); return }
      const end = buffer.indexOf(10)
      if (end < 0) return
      try {
        const value = JSON.parse(buffer.subarray(0, end).toString("utf8"))
        if (!value || typeof value.vox !== "string" || typeof value.room !== "string" || !Array.isArray(value.attention_receipts)) throw new Error("invalid envelope")
        settled = true
        enveloped = true
        clearTimeout(deadline)
        resolve(value)
      } catch { fail(new Error("Vox prepare returned an invalid envelope")) }
    })
    return promise
  }
  function sanitize(text) {
    return text.replace(/<(?=\s*\/?\s*(?:irc|system-[a-z][a-z-]*)(?![\w-]))/gi, "&lt;")
      .replace(/<(\/?)(vox-(?:room|notice|drive))/gi, "&lt;$1$2")
  }
  function markerCount(value, marker) {
    let count = 0, nodes = 0, bytes = 0
    const seen = new Set(), stack = [value]
    while (stack.length) {
      const item = stack.pop()
      if (++nodes > 100000) return -1
      if (typeof item === "string") {
        bytes += Buffer.byteLength(item)
        if (bytes > MAX_OUTPUT * 4) return -1
        let at = -1
        while ((at = item.indexOf(marker, at + 1)) !== -1) count++
      } else if (item && typeof item === "object") {
        if (seen.has(item)) return -1
        seen.add(item)
        for (const v of Object.values(item)) stack.push(v)
      }
    }
    return count
  }
  function report(reason) {
    try { ctx?.ui?.notify?.("Vox: " + reason, "warning") } catch {}
  }
  function hook(args, input = null) {
    const snapshot = generation
    const { promise, resolve, reject } = Promise.withResolvers()
    let child
    try { child = spawn(process.env.VOX_BIN || "vox", ["agent", "hook", "--node", VOX_NODE, ...args],
      { cwd: ctx.cwd, env: env(), stdio: ["pipe", "pipe", "pipe"] }) }
    catch (error) { reject(error); return promise }
    children.add(child)
    let output = [], size = 0, failed = false, stderrSize = 0
    const deadline = setTimeout(() => { failed = true; child.kill() }, REQUEST_WITHIN_MS)
    deadline.unref?.()
    child.stdout.on("data", chunk => {
      size += chunk.length
      if (size > MAX_OUTPUT) { failed = true; child.kill(); return }
      output.push(chunk)
    })
    // Drain without displaying untrusted diagnostic prose, which may contain private data.
    child.stderr.on("data", chunk => { stderrSize += chunk.length; if (stderrSize > MAX_OUTPUT) { failed = true; child.kill() } })
    child.stdin.on("error", () => {})
    child.stdin.end(input)
    child.once("error", error => { clearTimeout(deadline); children.delete(child); reject(error) })
    child.once("close", code => {
      clearTimeout(deadline); children.delete(child)
      if (failed || snapshot !== generation || !current()) return reject(Object.assign(new Error("Vox hook unavailable or session changed"), { temporary: true }))
      if (code !== 0) return reject(Object.assign(new Error("Vox registration failed"), { temporary: code === 75 }))
      resolve(Buffer.concat(output).toString("utf8"))
    })
    return promise
  }
  function cancelRetry() {
    clearTimeout(retryTimer)
    retryTimer = null
  }
  function scheduleRetry() {
    if (retryTimer || stopped || confirmed || refusal === "permanent" || !watcher) return
    const delay = [1, 2, 4, 8, 16, 30][Math.min(retryStep++, 5)] * 1000
    retryTimer = setTimeout(() => {
      retryTimer = null
      if (stopped || !watcher || confirmed || refusal === "permanent") return
      if (!generationRef && installPending) { void installPending(); return }
      void watcherCommand({ op: "snapshot" }).catch(error => {
        if (error.reason === "unavailable") scheduleRetry()
        else failWatcher("availability observation failed")
      })
    }, delay)
    retryTimer.unref?.()
  }
  function failWatcher(reason) {
    const ambiguous = poisoned || !!operation?.injected
    retire()
    poisoned = ambiguous
    readyNode = false
    report(reason)
    if (watcher) { watcher.stdin.destroy(); watcher.kill() }
  }
  function watcherCommand(command) {
    const child = watcher
    if (!child || child.stdin.destroyed) return Promise.reject(new Error("Vox ownership unavailable"))
    const id = String(++commandId)
    const { promise, resolve, reject } = Promise.withResolvers()
    const timer = setTimeout(() => {
      commands.delete(id)
      reject(new Error("Vox ownership command timed out"))
    }, REQUEST_WITHIN_MS)
    timer.unref?.()
    commands.set(id, { resolve, reject, timer })
    child.stdin.write(JSON.stringify({ id, ...command }) + "\n", error => {
      if (error && commands.has(id)) {
        commands.delete(id); clearTimeout(timer); reject(error)
      }
    })
    return promise
  }
  function startWatcher(successor = false, previousInstance = null) {
    if (watcher || stopped || !ctx) return watcherReady
    if (watcherFailed) return Promise.reject(new Error("Vox ownership unavailable"))
    const started = Promise.withResolvers()
    watcherReady = started.promise
    let child
    try {
      child = spawn(process.env.VOX_BIN || "vox", ["agent", "omp-watch", "--node", VOX_NODE, ...(successor ? ["--successor", "--instance", previousInstance] : [])],
        { cwd: ctx.cwd, env: process.env, stdio: ["pipe", "pipe", "pipe"] })
    } catch {
      watcherFailed = true
      started.reject(new Error("Vox availability helper could not start"))
      report("availability helper could not start; restart OMP and resume this conversation")
      return watcherReady
    }
    watcher = child
    let text = "", stderrSize = 0, owned = false
    const ownerDeadline = setTimeout(() => failWatcher("availability helper did not acquire ownership"), REQUEST_WITHIN_MS)
    ownerDeadline.unref?.()
    child.stdin.on("error", () => failWatcher("availability helper pipe failed"))
    child.stderr.on("data", chunk => { stderrSize += chunk.length; if (stderrSize > MAX_OUTPUT) failWatcher("availability helper exceeded its output limit") })
    child.stdout.on("data", chunk => {
      text += chunk.toString("utf8")
      if (Buffer.byteLength(text) > MAX_FRAME) return failWatcher("availability helper returned an oversized frame")
      let end
      while ((end = text.indexOf("\n")) !== -1) {
        const line = text.slice(0, end); text = text.slice(end + 1)
        let frame
        try { frame = JSON.parse(line) } catch { failWatcher("availability helper returned an invalid frame"); return }
        if (frame?.type === "owner" && !owned && /^[0-9a-f]{64}$/.test(frame.instance)) {
          clearTimeout(ownerDeadline); owned = true; instance = frame.instance; started.resolve()
        } else if (frame?.type === "ack" && typeof frame.id === "string") {
          const command = commands.get(frame.id)
          if (!command) continue
          commands.delete(frame.id); clearTimeout(command.timer)
          if (frame.ok === true) command.resolve()
          else command.reject(Object.assign(new Error("Vox ownership command refused"), { reason: frame.reason, temporary: frame.reason === "busy" }))
        } else if (frame?.type === "matched") {
          mismatchEpisode = false
        } else if (frame?.type === "ready") {
          readyNode = true
          mismatchEpisode = false
          if (refusal === "mismatch") refusal = null
          if (!current() && ctx?.mode === "tui" && ctx?.agent.kind === "main") void reconcileManager()
          else if (!confirmed && !retryTimer && refusal !== "permanent") void register()
        } else if (frame?.type === "unavailable") {
          readyNode = false; confirmed = false; availabilityEpoch++
          if (frame.reason === "mismatch") {
            if (refusal !== "mismatch") report("Vox update mismatch; update Vox and restart the daemon")
            refusal = "mismatch"
          }
        } else { failWatcher("availability helper returned an invalid frame"); return }
      }
    })
    child.once("error", () => { if (!owned) started.reject(new Error("Vox availability helper could not start")) })
    child.once("close", code => {
      clearTimeout(ownerDeadline)
      if (watcher !== child) return
      const previousInstance = instance
      const ambiguous = poisoned || !!operation?.injected
      retire()
      poisoned = ambiguous
      watcher = null; instance = null; readyNode = false
      for (const command of commands.values()) { clearTimeout(command.timer); command.reject(new Error("Vox ownership ended")) }
      commands.clear()
      if (!owned) started.reject(new Error("Vox availability helper ended"))
      if (stopped) return
      if (code === 76 && !mismatchEpisode) {
        mismatchEpisode = true
        report("Vox update detected; reconnecting availability helper")
        successorPending = true
        const successor = Promise.withResolvers()
        void successor.promise.catch(() => {})
        watcherReady = successor.promise
        const timer = setTimeout(() => {
          if (stopped) { successor.reject(new Error("Vox stopped")); return }
          const started = startWatcher(true, previousInstance)
          successorPending = false
          void started.then(() => { successor.resolve(); return reconcileManager() }).catch(error => {
            successor.reject(error); report("Vox availability helper could not recover")
          })
        }, 1000)
        timer.unref?.()
      } else { watcherFailed = true; report("Vox availability helper stopped; restart OMP and resume this conversation") }
    })
    return watcherReady
  }
  async function register() {
    if (!listening || !current() || !readyNode || !instance || !generationRef || refusal === "permanent" || refusal === "mismatch") return
    if (confirmed) return
    if (registration) return registration
    const id = session, stamp = generation, reference = generationRef, observation = availabilityEpoch
    const attempt = hook(["--session", id, "--attention-register"]).then(() => {
      if (stamp === generation && reference === generationRef && observation === availabilityEpoch && current() && readyNode) {
        confirmed = true; refusal = null; retryStep = 0; cancelRetry()
      }
    }).catch(error => {
      if (stamp !== generation || reference !== generationRef || observation !== availabilityEpoch || !current() || refusal === "mismatch") return
      confirmed = false
      refusal = error.temporary ? "temporary" : "permanent"
      report(error.temporary ? "registration temporarily unavailable; retrying when the node is ready" : "registration refused; check node identity, permissions and Vox version")
      if (error.temporary) scheduleRetry()
    }).finally(() => {
      if (registration === attempt) registration = null
      if ((stamp !== generation || observation !== availabilityEpoch) && readyNode && generationRef) void register()
    })
    registration = attempt
    return attempt
  }
  function retire() {
    generation++
    route = randomBytes(32).toString("hex")
    generationRef = null; installPending = null; confirmed = false; refusal = null; retryStep = 0; cancelRetry()
    if (operation) finish(operation, operation.injected ? null : "cancel")
    notices.clear()
    lastName = null
    tools.clear()
    for (const follower of followers) follower.destroy()
    followers.clear()
    for (const child of children) child.kill()
  }
  function reconcileManager() {
    if (stopped || !ctx) return Promise.resolve()
    retire()
    session = ctx.mode === "tui" && ctx.agent.kind === "main" ? ctx.sessionManager.getSessionId() : null
    transitionFence = session ? { leaf: ctx.sessionManager.getLeafId(), existing: new Set(ctx.sessionManager.getEntries().map(entry => entry.id)) } : null
    const stamp = generation, id = session, nextRoute = route
    ownership = ownership.catch(() => {}).then(async () => {
      if (!watcher && !successorPending) await startWatcher()
      else await watcherReady
      await watcherCommand({ op: "revoke" })
      if (stamp !== generation || !id || !current()) return
      const install = async () => {
        if (stamp !== generation || !current() || installPending !== install) return
        const reference = randomBytes(32).toString("hex")
        try {
          await watcherCommand({ op: "install", generation: reference, session: id, endpoint: socketPath, token, route: nextRoute })
          if (stamp !== generation || !current()) return
          installPending = null; generationRef = reference; retryStep = 0
          if (readyNode) void register()
        } catch (error) {
          if (stamp !== generation) return
          if (error.temporary) { report("Vox Session ownership temporarily unavailable"); scheduleRetry() }
          else { installPending = null; report("Vox Session ownership refused") }
        }
      }
      installPending = install
      await install()
    }).catch(() => { if (stamp === generation) { generationRef = null; report("Vox Session ownership unavailable") } })
    return ownership
  }
  function activate(next) {
    clearTimeout(reconciliationTimer)
    reconciliationTimer = null
    ctx = next
    void reconcileManager()
  }
  function publish(event) {
    send({ type: "event", event })
  }
  function send(frame) {
    if (!current()) return
    let line
    try { line = JSON.stringify(frame) + "\n" } catch { return }
    if (Buffer.byteLength(line) > MAX_OUTPUT) {
      for (const follower of followers) follower.destroy()
      followers.clear()
      return
    }
    for (const follower of followers) {
      if (follower.writableLength + Buffer.byteLength(line) > MAX_OUTPUT) follower.destroy()
      else follower.write(line)
    }
  }
  const server = createServer(sock => {
    if (sockets.size >= MAX_CONNECTIONS) return sock.destroy()
    sockets.add(sock)
    let authenticated = false, subscribed = false, handled = false, bytes = 0, text = ""
    const decoder = new StringDecoder("utf8")
    const timer = setTimeout(() => sock.destroy(), REQUEST_WITHIN_MS)
    timer.unref?.()
    const reply = value => { if (!sock.destroyed) sock.write(JSON.stringify(value) + "\n") }
    sock.on("error", () => {})
    sock.on("close", () => {
      clearTimeout(timer); sockets.delete(sock); followers.delete(sock)
      for (const [id, pending] of materializations) {
        if (pending.socket === sock) {
          materializations.delete(id)
          pending.reject(new Error("The authorized Drive connection closed"))
        }
      }
    })
    sock.on("data", data => {
      bytes += data.length
      if (bytes > MAX_FRAME) return sock.destroy()
      text += decoder.write(data)
      let index
      while ((index = text.indexOf("\n")) >= 0) {
        const line = text.slice(0, index); text = text.slice(index + 1); bytes = Buffer.byteLength(text)
        let msg
        try { msg = JSON.parse(line) } catch { return sock.destroy() }
        if (!authenticated) {
          const got = typeof msg?.token === "string" ? Buffer.from(msg.token) : Buffer.alloc(0)
          if (msg?.type !== "auth" || got.length !== expected.length || !timingSafeEqual(got, expected)) return sock.destroy()
          authenticated = true
          continue
        }
        if (subscribed) {
          if (msg?.type === "materialized") {
            const pending = materializations.get(msg.id)
            if (!pending || pending.socket !== sock) return sock.destroy()
            materializations.delete(msg.id)
            if (msg.ok === true && typeof msg.text === "string" && msg.text.trim()
              && typeof msg.room === "string"
              && (msg.operator === null || typeof msg.operator === "string")) {
              pending.resolve({ text: msg.text, operator: msg.operator, room: msg.room })
            }
            else pending.reject(new Error(typeof msg.error === "string" ? msg.error : "Drive authority is no longer valid"))
            continue
          }
          if (msg?.type !== "call" || !Number.isSafeInteger(msg.id) || !current()) return sock.destroy()
          const action = msg.action
          try {
            if (action?.type === "prompt") {
              const valid = typeof action.id === "string" && /^[0-9a-f]{32}$/.test(action.id)
              const accepted = valid && !poisoned && queue(action.id, "drive", "")
              reply({ type: "result", id: msg.id, ok: accepted,
                ...(accepted ? { value: "Private Drive request queued by Vox; native delivery is not confirmed" } : { error: "Vox bridge is unavailable or full" }) })
            } else if (action?.type === "abort") {
              ctx.abort()
              reply({ type: "result", id: msg.id, ok: true, value: "Abort requested; completion is not confirmed" })
            } else reply({ type: "result", id: msg.id, ok: false, error: "Unsupported Oh My Pi control" })
          } catch (error) { reply({ type: "result", id: msg.id, ok: false, error: String(error) }) }
          continue
        }
        if (handled) return sock.destroy()
        if (msg?.type === "route") {
          handled = true
          // A probe observes this exact route; it must not retire it or perform queue admission.
          // Temporary native work is not an ended conversation. Notice admission stays separate.
          reply(current() && generationRef && readyNode && msg.session === session && !poisoned
            ? { outcome: "available", session, route, client: route, admission: admissionAvailable() } : { outcome: "unavailable" })
          sock.end(); return
        }
        if (msg?.type === "subscribe") {
          if (!current() || !generationRef || !readyNode || msg.session !== session) return sock.destroy()
          subscribed = true; clearTimeout(timer); followers.add(sock)
          reply({ type: "subscribed", session })
          reply({ type: "event", event: { type: "state", busy: !ctx.isIdle() } })
          const name = pi.getSessionName()
          if (name) { lastName = name; reply({ type: "event", event: { type: "name", name } }) }
          continue
        }
        const valid = typeof msg?.id === "string" && /^[0-9a-f]{32}$/.test(msg.id)
        const answer = (outcome, error) => { reply({ id: valid ? msg.id : null, outcome, ...(error ? { error } : {}) }); sock.end() }
        if (msg?.type !== "attention" || !valid || typeof msg.text !== "string" || !msg.text.trim()
          || Buffer.byteLength(msg.text) > MAX_FRAME / 2) return answer("rejected", "Invalid attention frame")
        if (!current() || !generationRef || !readyNode || msg.session !== session || msg.route !== route || poisoned) return answer("unavailable", "The exact Session route is unavailable")
        const digest = createHash("sha256").update(msg.text).digest("hex")
        const prior = notices.get(msg.id)
        if (prior) return prior.digest !== digest ? answer("rejected", "Attention ID already used")
          : prior.state === "cancelled" ? answer("unavailable", "Attention was canceled by a Session transition") : answer("accepted")
        if (!queue(msg.id, "attention", msg.text)) return answer("unavailable", "Vox bridge queue is full")
        notices.get(msg.id).digest = digest
        return answer("accepted")
      }
    })
  })
  const { promise: ready, resolve: listeningResult } = Promise.withResolvers()
  server.on("error", () => { listeningResult(false) })
  server.listen(socketPath, () => {
    try { chmodSync(socketPath, 0o600); listening = true; listeningResult(true); void register() }
    catch { listeningResult(false); server.close() }
  })
  pi.on("session_start", async (_event, context) => {
    activate(context)
    if (await ready) { await ownership; await register() }
  })
  async function beforeTransition() {
    observeOrdinary()
    if (ordinarySensitive || operation?.injected) return { cancel: true }
    const op = operation
    retire()
    if (op?.closed) await op.closed
    const stamp = generation
    ownership = ownership.catch(() => {}).then(async () => {
      if (watcher) await watcherCommand({ op: "revoke" })
    }).catch(() => report("Vox Session retirement could not be confirmed"))
    await ownership
    // Native cancellation can leave the Manager unchanged without a compensating event.
    // Reconcile on the next turn; a real switch event supersedes this timer.
    reconciliationTimer = setTimeout(() => {
      reconciliationTimer = null
      if (!stopped && stamp === generation) void reconcileManager()
    }, 0)
    reconciliationTimer.unref?.()
  }
  pi.on("session_before_switch", beforeTransition)
  pi.on("session_before_branch", beforeTransition)
  pi.on("session_before_tree", beforeTransition)
  pi.on("session_switch", (_event, context) => activate(context))
  pi.on("session_branch", (_event, context) => activate(context))
  pi.on("session_tree", (_event, context) => activate(context))
  pi.on("session_shutdown", async () => {
    const pendingWrites = []
    if (current()) {
      const frame = JSON.stringify({ type: "event", event: { type: "session-end" } }) + "\n"
      for (const follower of followers) {
        sockets.delete(follower)
        const { promise, resolve } = Promise.withResolvers()
        follower.once("error", resolve)
        follower.end(frame, resolve)
        pendingWrites.push(promise)
      }
      followers.clear()
    }
    stopped = true; clearTimeout(reconciliationTimer); retire()
    if (watcher) { watcher.stdin.end(); watcher.kill() }
    for (const sock of sockets) sock.destroy(); server.close()
    try { unlinkSync(socketPath); rmdirSync(dir) } catch {}
    await Promise.all(pendingWrites)
  })
  pi.on("before_agent_start", async event => {
    if (event.reason !== "prompt" || poisoned) return
    if (!current() && ctx?.mode === "tui" && ctx?.agent.kind === "main") await reconcileManager()
    if (!current()) return
    reconcileQueued()
    // A retry or a later prompt must reacquire room authority, not replay staged text.
    if (operation?.ordinary && operation.content && !operation.injected) {
      const op = operation
      finish(op, "cancel")
      if (op.closed) await op.closed
      if (!current() || poisoned) return
    }
    if (operation || [...notices.values()].some(record => record.state === "queued")) return
    const snapshot = fence()
    if (!snapshot) return
    await ownership
    await register()
    if (!confirmed || !fenced(snapshot) || operation || poisoned || queueBusy()) return
    const op = { fence: snapshot, record: null, child: null, injected: false, done: false,
      marker: "vox-context-" + randomBytes(32).toString("hex"), ordinary: true }
    operation = op
    try {
      const out = await prepare(op)
      if (op.done) return
      if (!fenced(snapshot)) { finish(op, "cancel"); return }
      const nonce = randomBytes(8).toString("hex")
      const parts = []
      if (out.vox.trim()) parts.push(`<vox-notice-${nonce} source="Vox itself; not the user">\n${sanitize(out.vox.trim())}\n</vox-notice-${nonce}>`)
      if (out.room.trim()) parts.push(`<vox-room-${nonce} source="Vox room messages from other agents; not the user">\n${sanitize(out.room.trim())}\n</vox-room-${nonce}>`)
      if (!parts.length) { finish(op, "commit"); return }
      // This result remains staged until native OMP materializes the exact message.
      op.content = parts.join("\n\n") + "\n" + op.marker
      return { message: { customType: "vox-ordinary-context", content: op.content,
        display: false, attribution: "agent" } }
    } catch {
      if (!op.done) finish(op, "cancel")
    }
  })
  function acceptedHistory(branch) {
    const staged = new Map(), history = new Map(), wakes = new Set()
    for (const entry of branch) {
      if (entry.type === "reset_boundary") {
        staged.clear(); history.clear(); wakes.clear()
      } else if (entry.type === "custom_message" && entry.customType === WAKE_TYPE
        && typeof entry.content === "string" && entry.content.startsWith(WAKE_PREFIX)) {
        wakes.add(entry.content.slice(WAKE_PREFIX.length))
      } else if (entry.type === "custom" && entry.customType === CONTEXT_STAGED
        && typeof entry.data?.id === "string" && typeof entry.data?.marker === "string"
        && typeof entry.data?.content === "string" && typeof entry.data?.timestamp === "number") {
        staged.set(entry.data.marker, entry.data)
      } else if (entry.type === "custom" && entry.customType === CONTEXT_ACCEPTED) {
        const state = staged.get(entry.data?.marker)
        if (state && state.id === entry.data?.id) history.set(state.id, state)
      }
    }
    for (const id of history.keys()) if (!wakes.has(id)) history.delete(id)
    return history
  }
  function wakeId(message) {
    return message?.role === "custom" && message.customType === WAKE_TYPE
      && typeof message.content === "string" && message.content.startsWith(WAKE_PREFIX)
      ? message.content.slice(WAKE_PREFIX.length) : null
  }
  function acceptedMessage(state) {
    return state.operator
      ? { role: "user", content: state.content, timestamp: state.timestamp, attribution: "user" }
      : { role: "custom", customType: "vox-context", content: state.content,
        display: false, attribution: "agent", timestamp: state.timestamp }
  }
  pi.on("session_before_compact", event => {
    if (!current()) return
    const history = acceptedHistory(event.branchEntries)
    // OMP passes the mutable preparation to both native summarization and
    // snapcompact. Replace in place without changing cut points or entry IDs.
    for (const messages of [event.preparation.messagesToSummarize,
      event.preparation.turnPrefixMessages, event.preparation.recentMessages]) {
      for (let index = 0; index < messages.length; index++) {
        const state = history.get(wakeId(messages[index]))
        if (state) messages[index] = acceptedMessage(state)
      }
    }
  })
  pi.on("context", async event => {
    observeOrdinary()
    reconcileQueued()
    // Only reconstruct accepted materialization on the active, post-reset branch.
    // The event's own messages still decide what survives native compaction.
    const history = current() ? acceptedHistory(ctx.sessionManager.getBranch()) : new Map()
    const messages = [], matched = []
    let sawWake = false
    for (const message of event.messages) {
      if (message?.role === "custom" && message.customType === WAKE_TYPE) {
        sawWake = true
        const id = wakeId(message)
        const state = history.get(id)
        if (state) {
          messages.push(acceptedMessage(state))
        } else {
          const record = notices.get(id)
          if (record?.state === "queued" && fenced(record.fence)) matched.push({ record, index: messages.length })
        }
      } else messages.push(message)
    }
    if (!sawWake || !current() || operation || poisoned || matched.length !== 1) return { messages }
    const { record, index } = matched[0]
    const snapshot = record?.fence || fence()
    if (!snapshot || !fenced(snapshot)) return { messages }
    await ownership
    await register()
    if (!confirmed || !fenced(snapshot) || operation || poisoned) return { messages }
    // Only requests belonging to this new native step can acknowledge its marker.
    providerActive = 0
    const op = { fence: snapshot, record, child: null, injected: false, done: false,
      marker: "vox-context-" + randomBytes(32).toString("hex"), ambiguous: false, matched: false }
    operation = op
    if (record) record.state = "preparing"
    try {
      const nonce = randomBytes(8).toString("hex")
      const parts = []
      if (record.source !== "drive") {
        const out = await prepare(op)
        if (op.done) return { messages }
        if (!fenced(snapshot)) { finish(op, "cancel"); return { messages } }
        if (out.vox.trim()) parts.push(`<vox-notice-${nonce} source="Vox itself; not the user">\n${sanitize(out.vox.trim())}\n</vox-notice-${nonce}>`)
        if (out.room.trim()) parts.push(`<vox-room-${nonce} source="Vox room messages from other agents; not the user">\n${sanitize(out.room.trim())}\n</vox-room-${nonce}>`)
      }
      let operator = null
      if (record?.source === "drive") {
        const input = await materialize(record.id)
        if (op.done || !fenced(snapshot)) { if (!op.done) finish(op, "cancel"); return { messages } }
        operator = input.operator
        if (operator) {
          parts.push(`Vox private Drive operator node: ${operator}\nRoom: ${input.room}\nSession: ${session}\n\n${sanitize(input.text)}`)
        } else {
          parts.push(`<vox-drive-${nonce} source="Vox private Drive file notice; not the user">\n${sanitize(input.text)}\n</vox-drive-${nonce}>`)
        }
      }
      if (!parts.length) { finish(op, "cancel"); return { messages } }
      const content = parts.join("\n\n") + "\n" + op.marker, timestamp = Date.now()
      const state = { id: record.id, marker: op.marker, content, timestamp, operator }
      pi.appendEntry(CONTEXT_STAGED, state)
      messages.splice(index, 0, acceptedMessage(state))
      op.injected = true
      if (record) record.state = "dispatched"
      return { messages }
    } catch {
      if (!op.done) finish(op, "cancel")
      return { messages }
    }
  })
  pi.on("before_provider_request", event => {
    observeOrdinary()
    providerActive++
    const op = operation
    if (!op?.injected || op.ordinary) return
    if (providerActive !== 1 || op.matched) op.ambiguous = true
    const count = markerCount(event.payload, op.marker)
    if (count === 1 && !op.matched) op.matched = true
    else op.ambiguous = true
  })
  pi.on("message_end", event => {
    const op = operation
    if (op?.ordinary && event.message?.role === "custom"
      && event.message.customType === "vox-ordinary-context" && event.message.content === op.content) {
      op.injected = true
      op.observed = true
      observeOrdinary()
    }
    const m = event.message
    if (m?.role === "assistant") {
      if (op?.injected && !op.ordinary && op.matched) {
        // HTTP headers are not a completion signal for every transport (Codex uses WebSocket).
        // Unknown stop reasons remain uncertain rather than acknowledging an unproved delivery.
        let commit = providerActive === 1 && !op.ambiguous && fenced(op.fence)
          && !m.errorMessage && ["stop", "toolUse", "length"].includes(m.stopReason)
        if (commit) {
          try { pi.appendEntry(CONTEXT_ACCEPTED, { id: op.record.id, marker: op.marker }) }
          catch { commit = false }
        }
        finish(op, commit ? "commit" : null)
      }
      providerActive = 0
    }
    if (m?.role !== "user" && m?.role !== "assistant") return
    const text = Array.isArray(m.content) ? m.content.filter(part => part.type === "text").map(part => part.text).join("") : typeof m.content === "string" ? m.content : ""
    if (text) publish({ type: m.role === "user" ? "user" : "reply", text })
  })
  pi.on("tool_execution_start", event => {
    if (!current()) return
    tools.set(event.toolCallId, generation)
    publish({ type: "tool", id: event.toolCallId, name: event.toolName, input: JSON.stringify(event.args) ?? "" })
  })
  pi.on("tool_execution_end", event => {
    const stamp = tools.get(event.toolCallId)
    tools.delete(event.toolCallId)
    if (stamp !== generation || !current()) return
    publish({ type: "tool-done", id: event.toolCallId, name: event.toolName, output: JSON.stringify(event.result) ?? "", isError: !!event.isError })
  })
  pi.on("agent_start", () => publish({ type: "turn-start" }))
  pi.on("agent_end", event => {
    observeOrdinary()
    const name = pi.getSessionName()
    if (name && name !== lastName) { lastName = name; publish({ type: "name", name }) }
    if (!event.willContinue && !event.awaitingAsyncWork && operation) finish(operation, operation.injected ? null : "cancel")
    if (!event.willContinue && !event.awaitingAsyncWork) providerActive = 0
    if (!event.willContinue && !event.awaitingAsyncWork) ordinarySensitive = false
    if (!event.willContinue && !event.awaitingAsyncWork) publish({ type: "turn-end" })
  })
}
