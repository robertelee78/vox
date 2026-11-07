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
const MAX_POISONED_SESSIONS = 128
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
  let commandId = 0, commands = new Map(), installPending = null, revokePending = null
  let availabilityEpoch = 0, successorPending = false
  let reconcileSerial = 0, ownershipNotice = false, unavailableNotice = false, installed = false
  let cleanupCertain = true
  const token = randomBytes(32).toString("hex")
  const expected = Buffer.from(token)
  const notices = new Map(), materializations = new Map()
  const poisonedSessions = new Set()
  let poisonOverflow = false
  let operation = null, providerActive = 0, transitionFence = null

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
    && installed
    && ctx?.sessionManager.getSessionId() === session && !!session
    && !!transitionFence && branchMatches(ctx.sessionManager, transitionFence)
  function isPoisoned() { return poisonOverflow || poisonedSessions.has(session) }
  function poisonSession(id) {
    if (typeof id !== "string" || !id || (!poisonedSessions.has(id) && poisonedSessions.size >= MAX_POISONED_SESSIONS)) {
      if (!poisonOverflow) report("delivery is uncertain; start a new native OMP conversation to use Vox. Restarting or resuming cannot confirm earlier delivery")
      poisonOverflow = true
      return
    }
    if (poisonedSessions.has(id)) return
    poisonedSessions.add(id)
    report("delivery in this conversation is uncertain; start a new native OMP conversation to use Vox. Restarting or resuming cannot confirm earlier delivery")
  }
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
    return resetBoundary(branch) === stamp.reset
      && (stamp.leaf === null || anchor !== -1)
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
      const frame = JSON.stringify({ type: "discard", id: record.id }) + "\n"
      for (const follower of followers) {
        if (follower.writableLength + Buffer.byteLength(frame) > MAX_OUTPUT) follower.destroy()
        else follower.write(frame)
      }
    }
    notices.delete(record.id)
  }
  function reconcileQueued() {
    if (!current()) {
      for (const record of notices.values()) {
        if (record.state === "queued") { record.state = "cancelled"; retireNotice(record) }
      }
      return
    }
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
    if (queueBusy() || notices.has(id) || notices.size >= MAX_NOTICES || operation || !current() || !generationRef || !readyNode || !confirmed) return false
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
    if (!command) poisonSession(op.fence?.session)
    // Keep ownership until the hook confirms either decision and exits.
    if (!op.child && operation === op) operation = null
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
    if (op.record?.source === "drive") e.VOX_OMP_DRIVE = "1"
    else delete e.VOX_OMP_DRIVE
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
      if (!enveloped && code === 78) {
        poisonSession(op.fence?.session)
      } else if (!enveloped && fenced(op.fence)) {
        confirmed = false
        report(code === 75 ? "Session registration is no longer present; reacquiring it" : "context preparation unavailable; reacquiring registration")
        scheduleRetry()
      }
      if (!settled) fail(new Error("Vox prepare ended before its envelope"))
      if (op.decision === "commit" || op.decision === "cancel") {
        const confirmed = enveloped && code === 0
        if (op.record) op.record.state = confirmed ? (op.decision === "commit" ? "committed" : "cancelled") : "unknown"
        if (!confirmed && enveloped) {
          poisonSession(op.fence?.session)
          if (op.fence?.session === session) publish({ type: "unavailable", error: "Vox context " + op.decision + " was not confirmed" })
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
    child.once("error", error => { cleanupCertain = false; clearTimeout(deadline); children.delete(child); reject(error) })
    child.once("close", code => {
      clearTimeout(deadline); children.delete(child)
      if (failed || code !== 0) cleanupCertain = false
      if (code === 78) return reject(Object.assign(new Error("Vox delivery is uncertain"), { uncertain: true }))
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
      if (revokePending) { void revokePending(); return }
      if (!generationRef && installPending) { void installPending(); return }
      void watcherCommand({ op: "snapshot" }).catch(error => {
        if (error.reason === "unavailable" || error.reason === "busy") scheduleRetry()
        else failWatcher("availability observation failed")
      })
    }, delay)
    retryTimer.unref?.()
  }
  function failWatcher(reason) {
    retire()
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
          if (current() && generationRef && !confirmed && !retryTimer && refusal !== "permanent") void register()
        } else if (frame?.type === "unavailable") {
          readyNode = false; confirmed = false; availabilityEpoch++
          if (frame.reason === "mismatch") {
            if (refusal !== "mismatch") report("Vox update mismatch; update Vox and restart the daemon")
            refusal = "mismatch"
          } else if (current() && !unavailableNotice) {
            unavailableNotice = true
            report(`node ${VOX_NODE} is unavailable. If it has not been created, run \`vox node create -- ${VOX_NODE}\`; otherwise run \`vox node unlock -- ${VOX_NODE}\` in a terminal. If the daemon is not answering, restart it. Creating a node makes a new identity.`)
          }
        } else { failWatcher("availability helper returned an invalid frame"); return }
      }
    })
    child.once("error", () => { if (!owned) started.reject(new Error("Vox availability helper could not start")) })
    child.once("close", code => {
      clearTimeout(ownerDeadline)
      if (watcher !== child) return
      const previousInstance = instance
      const succession = code === 76 && !mismatchEpisode && !stopped
      const ownerSerial = reconcileSerial, ownerGeneration = generation, ownerSession = session, ownerRoute = route
      if (succession) {
        generationRef = null; installPending = null; confirmed = false; readyNode = false; availabilityEpoch++
        cancelRetry()
        if (operation) finish(operation, operation.injected ? null : "cancel")
        for (const follower of followers) follower.destroy()
        followers.clear()
        for (const child of children) child.kill()
      } else retire()
      watcher = null; instance = null; readyNode = false
      for (const command of commands.values()) { clearTimeout(command.timer); command.reject(new Error("Vox ownership ended")) }
      commands.clear()
      if (!owned) started.reject(new Error("Vox availability helper ended"))
      if (stopped) {
        if (owned && previousInstance && cleanupCertain && children.size === 0) {
          try {
            const cleaner = spawn(process.env.VOX_BIN || "vox", ["agent", "omp-watch", "--node", VOX_NODE, "--cleanup", "--instance", previousInstance],
              { cwd: ctx.cwd, env: process.env, stdio: "ignore" })
            cleaner.on("error", () => {})
            const deadline = setTimeout(() => cleaner.kill(), REQUEST_WITHIN_MS)
            deadline.unref?.()
            cleaner.once("close", () => clearTimeout(deadline))
          } catch {}
        }
        return
      }
      if (succession) {
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
          void started.then(async () => {
            successor.resolve()
            if (ownerSerial !== reconcileSerial || ownerGeneration !== generation || session !== ownerSession || route !== ownerRoute || !current()) return
            await bindOwnership(ownerSerial, ownerGeneration, ownerSession, ownerRoute)
          }).catch(error => {
            successor.reject(error); report("Vox availability helper could not recover")
          })
        }, 1000)
        timer.unref?.()
      } else { watcherFailed = true; report("Vox availability helper stopped; restart OMP and resume this conversation") }
    })
    return watcherReady
  }
  async function register() {
    if (!listening || !current() || !instance || !generationRef || refusal === "permanent" || refusal === "mismatch") return
    if (confirmed) return
    if (registration) return registration
    const id = session, stamp = generation, reference = generationRef, observation = availabilityEpoch
    const attempt = hook(["--session", id, "--attention-register"]).then(async () => {
      if (stamp !== generation || reference !== generationRef || observation !== availabilityEpoch || !current()) return
      await hook(["--session", id, "--omp-check-uncertainty"])
      if (stamp === generation && reference === generationRef && observation === availabilityEpoch && current()) {
        confirmed = true; refusal = null; retryStep = 0; cancelRetry()
      }
    }).catch(error => {
      if (error.uncertain) {
        poisonSession(id)
        if (stamp === generation && reference === generationRef) { confirmed = false; refusal = "permanent" }
        return
      }
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
    for (const record of notices.values()) {
      if (record.source === "drive" && (record.state === "queued" || (record.state === "preparing" && !operation?.injected))) {
        record.state = "cancelled"
        retireNotice(record)
      }
    }
    generation++
    installed = false
    route = randomBytes(32).toString("hex")
    generationRef = null; installPending = null; revokePending = null; confirmed = false; refusal = null; retryStep = 0; unavailableNotice = false; cancelRetry()
    if (operation) finish(operation, operation.injected ? null : "cancel")
    notices.clear()
    lastName = null
    tools.clear()
    for (const follower of followers) follower.destroy()
    followers.clear()
    for (const child of children) child.kill()
  }
  function bindOwnership(serial, stamp, id, nextRoute) {
    let running = null, revoked = false
    const install = () => {
      if (running) return running
      if (serial !== reconcileSerial || stamp !== generation || !current() || installPending !== install) return Promise.resolve()
      running = (async () => {
        try {
          if (!revoked) {
            await watcherCommand({ op: "revoke" })
            if (serial !== reconcileSerial || stamp !== generation || !current()) return
            revoked = true
          }
          const reference = randomBytes(32).toString("hex")
          await watcherCommand({ op: "install", generation: reference, session: id, endpoint: socketPath, token, route: nextRoute })
          if (serial !== reconcileSerial || stamp !== generation || !current()) return
          installPending = null; generationRef = reference; retryStep = 0; ownershipNotice = false
          void register()
        } catch (error) {
          if (serial !== reconcileSerial || stamp !== generation || !current()) return
          if (error.temporary) {
            if (readyNode && !ownershipNotice) { report("Vox Session ownership temporarily unavailable"); ownershipNotice = true }
            scheduleRetry()
          } else { installPending = null; report("Vox Session ownership refused") }
        }
      })().finally(() => { running = null })
      return running
    }
    installPending = install
    return install()
  }
  function reconcileManager() {
    if (stopped || !ctx || ctx.mode !== "tui" || ctx.agent.kind !== "main") return Promise.resolve()
    const manager = ctx.sessionManager
    const id = manager.getSessionId(), leaf = manager.getLeafId(), branch = manager.getBranch()
    const snapshot = id ? { leaf, reset: resetBoundary(branch), existing: new Set(manager.getEntries().map(entry => entry.id)) } : null
    const serial = ++reconcileSerial
    retire()
    session = id
    transitionFence = snapshot
    installed = !!id
    const stamp = generation, nextRoute = route
    const work = (async () => {
      if (!id || !current()) return
      if (!watcher && !successorPending) await startWatcher()
      else await watcherReady
      if (serial !== reconcileSerial || stamp !== generation || !current()) return
      await bindOwnership(serial, stamp, id, nextRoute)
    })().catch(() => { if (serial === reconcileSerial) { generationRef = null; report("Vox Session ownership unavailable") } })
    ownership = work
    return work
  }
  function activate(next) {
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
            else {
              if (msg.ok === false && current()) {
                const stamp = fence()
                const reason = "Vox refused a queued private Drive input before delivery; it was unavailable or its authority or Session changed."
                report(reason)
                const show = () => {
                  if (!fenced(stamp)) return
                  if (!ctx.isIdle()) {
                    const timer = setTimeout(show, 100)
                    timer.unref?.()
                    return
                  }
                  pi.sendMessage({ customType: "vox-drive-refused", content: reason, display: true, attribution: "agent" }, { triggerTurn: false })
                }
                setTimeout(show, 0)
              }
              pending.reject(new Error(typeof msg.error === "string" ? msg.error : "Drive authority is no longer valid"))
            }
            continue
          }
          if (msg?.type !== "call" || !Number.isSafeInteger(msg.id) || !current()) return sock.destroy()
          const action = msg.action
          try {
            if (action?.type === "prompt") {
              const valid = typeof action.id === "string" && /^[0-9a-f]{32}$/.test(action.id)
              const accepted = valid && !isPoisoned() && queue(action.id, "drive", "")
              reply({ type: "result", id: msg.id, ok: accepted,
                ...(accepted ? { value: "Private Drive request queued by Vox; native delivery is not confirmed" } : { code: "not-queued", error: "Vox bridge is unavailable or full" }) })
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
          reply(current() && generationRef && readyNode && confirmed && msg.session === session && !isPoisoned()
            ? { outcome: "available", session, route, client: route, admission: admissionAvailable() } : { outcome: "unavailable" })
          sock.end(); return
        }
        if (msg?.type === "subscribe") {
          if (!current() || !generationRef || !readyNode || msg.session !== session) return sock.destroy()
          handled = true
          const id = session, stamp = generation, reference = generationRef
          const admit = () => {
            if (sock.destroyed || !current() || session !== id || generation !== stamp
              || generationRef !== reference || !readyNode || !confirmed || isPoisoned()) return sock.destroy()
            subscribed = true; clearTimeout(timer); followers.add(sock)
            reply({ type: "subscribed", session })
            reply({ type: "event", event: { type: "state", busy: !ctx.isIdle() } })
            // Enroll before the snapshot so later live events follow recoverable receipts.
            const accepted = [...acceptedHistory(ctx.sessionManager.getBranch()).values()].slice(-MAX_NOTICES / 4)
            for (const state of accepted) {
              if (typeof state.response === "string")
                reply({ type: "event", event: { type: "drive-accepted", id: state.id, response: state.response } })
            }
            const name = pi.getSessionName()
            if (name) { lastName = name; reply({ type: "event", event: { type: "name", name } }) }
          }
          if (confirmed) admit()
          else if (registration) void registration.then(admit, () => sock.destroy())
          else sock.destroy()
          continue
        }
        const valid = typeof msg?.id === "string" && /^[0-9a-f]{32}$/.test(msg.id)
        const answer = (outcome, error) => { reply({ id: valid ? msg.id : null, outcome, ...(error ? { error } : {}) }); sock.end() }
        if (msg?.type !== "attention" || !valid || typeof msg.text !== "string" || !msg.text.trim()
          || Buffer.byteLength(msg.text) > MAX_FRAME / 2) return answer("rejected", "Invalid attention frame")
        if (!current() || !generationRef || !readyNode || !confirmed || msg.session !== session || msg.route !== route || isPoisoned()) return answer("unavailable", "The exact Session route is unavailable")
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
  function beforeTransition(_event, context) {
    ctx = context
    if (operation?.injected) {
      report("finish the current Vox delivery before switching conversations")
      return { cancel: true }
    }
    const serial = ++reconcileSerial
    retire()
    const owner = watcher
    if (owner) {
      let running = false
      const revoke = async () => {
        if (running || serial !== reconcileSerial || watcher !== owner || revokePending !== revoke) return
        running = true
        try {
          await watcherCommand({ op: "revoke" })
          if (serial === reconcileSerial && revokePending === revoke) revokePending = null
        } catch (error) {
          if (serial !== reconcileSerial || watcher !== owner || revokePending !== revoke) return
          if (error.temporary) scheduleRetry()
          else { revokePending = null; report("Vox Session retirement could not be confirmed") }
        } finally { running = false }
      }
      revokePending = revoke
      void revoke()
    }
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
    stopped = true; retire()
    if (watcher) {
      const child = watcher
      child.stdin.end()
      const deadline = setTimeout(() => child.kill(), 1000)
      deadline.unref?.()
      child.once("close", () => clearTimeout(deadline))
    }
    for (const sock of sockets) sock.destroy(); server.close()
    try { unlinkSync(socketPath); rmdirSync(dir) } catch {}
    await Promise.all(pendingWrites)
  })
  pi.on("before_agent_start", async event => {
    if (event.reason !== "prompt") return
    if (!current() && ctx?.mode === "tui" && ctx?.agent.kind === "main") await reconcileManager()
    if (!current() || isPoisoned()) return
    await ownership
    if (!current()) return
    await register()
    // A marker returned to an earlier prompt may have been dropped by OMP before context.
    // It carries no content, so the next real prompt can retire it without replay.
    for (const record of notices.values()) {
      if (record.source === "ordinary" && record.state === "queued") {
        record.state = "cancelled"
        retireNotice(record)
      }
    }
    reconcileQueued()
    if (operation || [...notices.values()].some(record => record.state === "queued")) return
    const snapshot = fence()
    if (!snapshot) return
    if (!confirmed || !fenced(snapshot) || operation || isPoisoned() || queueBusy()) return
    const id = randomBytes(16).toString("hex")
    notices.set(id, { id, source: "ordinary", text: "", fence: snapshot, state: "queued" })
    return { message: { customType: WAKE_TYPE, content: WAKE_PREFIX + id, display: false, attribution: "agent" } }
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
        if (state && state.id === entry.data?.id)
          history.set(state.id, { ...state, response: entry.data?.response })
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
    if (!sawWake || !current() || operation || isPoisoned() || matched.length !== 1) return { messages }
    const { record, index } = matched[0]
    const snapshot = record?.fence || fence()
    if (!snapshot || !fenced(snapshot)) return { messages }
    await ownership
    if (!fenced(snapshot) || isPoisoned()) return { messages }
    await register()
    if (!confirmed || !fenced(snapshot) || operation || isPoisoned()) return { messages }
    // Only requests belonging to this new native step can acknowledge its marker.
    providerActive = 0
    const op = { fence: snapshot, record, child: null, injected: false, done: false,
      marker: "vox-context-" + randomBytes(32).toString("hex"), ambiguous: false, matched: false }
    operation = op
    if (record) record.state = "preparing"
    try {
      const nonce = randomBytes(8).toString("hex")
      const parts = []
      {
        const out = await prepare(op)
        if (op.done) return { messages }
        if (!fenced(snapshot)) { finish(op, "cancel"); return { messages } }
        if (record.source !== "drive" && out.vox.trim()) parts.push(`<vox-notice-${nonce} source="Vox itself; not the user">\n${sanitize(out.vox.trim())}\n</vox-notice-${nonce}>`)
        if (record.source !== "drive" && out.room.trim()) parts.push(`<vox-room-${nonce} source="Vox room messages from other agents; not the user">\n${sanitize(out.room.trim())}\n</vox-room-${nonce}>`)
      }
      let operator = null
      if (record?.source === "drive") {
        const input = await materialize(record.id)
        if (op.done || !fenced(snapshot)) { if (!op.done) finish(op, "cancel"); return { messages } }
        operator = input.operator
        if (operator) {
          parts.push(`Vox private Drive provenance ${nonce} — operator node: ${operator}\nRoom: ${input.room}\nSession: ${session}\n\n<vox-drive-${nonce} source="authenticated operator text">\n${sanitize(input.text)}\n</vox-drive-${nonce}>`)
        } else {
          parts.push(`<vox-drive-${nonce} source="Vox private Drive file notice; not the user">\n${sanitize(input.text)}\n</vox-drive-${nonce}>`)
        }
      }
      if (!parts.length) { finish(op, "cancel"); return { messages } }
      if (op.done || !current() || !fenced(snapshot)) { if (!op.done) finish(op, "cancel"); return { messages } }
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
    providerActive++
    const op = operation
    if (op?.injected && !fenced(op.fence)) {
      finish(op, null)
      ctx?.abort()
      return
    }
    if (!op?.injected) return
    if (providerActive !== 1 || op.matched) op.ambiguous = true
    const count = markerCount(event.payload, op.marker)
    if (count === 1 && !op.matched) op.matched = true
    else op.ambiguous = true
  })
  pi.on("message_end", event => {
    const op = operation
    const m = event.message
    if (m?.role === "assistant") {
      if (op?.injected && op.matched) {
        // HTTP headers are not a completion signal for every transport (Codex uses WebSocket).
        // Unknown stop reasons remain uncertain rather than acknowledging an unproved delivery.
        let commit = providerActive === 1 && !op.ambiguous && fenced(op.fence)
          && !m.errorMessage && ["stop", "toolUse", "length"].includes(m.stopReason)
        const response = Array.isArray(m.content)
          ? m.content.filter(part => part.type === "text").map(part => part.text).join("")
          : typeof m.content === "string" ? m.content : ""
        const chars = Array.from(response)
        const bounded = chars.length > 8192
          ? chars.slice(0, 8192).join("") + "\n[Response step truncated at the transport bound]"
          : response
        if (commit) {
          try { pi.appendEntry(CONTEXT_ACCEPTED, { id: op.record.id, marker: op.marker, response: bounded }) }
          catch { commit = false }
        }
        if (commit && op.record?.source === "drive")
          publish({ type: "drive-accepted", id: op.record.id, response: bounded })
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
    const name = pi.getSessionName()
    if (name && name !== lastName) { lastName = name; publish({ type: "name", name }) }
    if (!event.willContinue && !event.awaitingAsyncWork && operation) finish(operation, operation.injected ? null : "cancel")
    if (!event.willContinue && !event.awaitingAsyncWork) providerActive = 0
    if (!event.willContinue && !event.awaitingAsyncWork) publish({ type: "turn-end" })
  })
}
