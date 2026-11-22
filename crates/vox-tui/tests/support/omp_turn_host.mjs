// Minimal Oh My Pi host shim (rebuilt from RcaTrust's shim-hold.mjs after the 2026-11-13 reboot):
// implements exactly the `pi`/`ctx` surface omp-extension.ts uses, and drives turns the way OMP
// drives them. Commands on stdin, one per line:
//   turn <text>   a user prompt turn
//   quit          session_shutdown
// With RCA_HOLD_FILE set, an armed turn holds after context until the proof releases it.
// This is a host stand-in, not a model; the real shipped extension and hook own delivery.
import { pathToFileURL } from "node:url"
import { createInterface } from "node:readline"
import { existsSync, unlinkSync } from "node:fs"

const [extPath, SESSION, CWD] = process.argv.slice(2)
const T0 = Date.now()
const stamp = () => new Date().toISOString().slice(11, 23)
const log = (kind, ...rest) => console.log(`${stamp()} +${((Date.now() - T0) / 1000).toFixed(3)}s ${kind}: ${rest.map(r => typeof r === "string" ? r : JSON.stringify(r)).join(" ")}`)

const handlers = new Map()
const branch = []
let nextId = 1
let idle = true
const push = e => { e.id = String(nextId++); branch.push(e); return e }

const pi = {
  on(ev, fn) { if (!handlers.has(ev)) handlers.set(ev, []); handlers.get(ev).push(fn) },
  sendMessage(msg, opts) {
    log("sendMessage", { customType: msg.customType, content: msg.content, display: msg.display, opts })
    push({ type: "custom_message", customType: msg.customType, content: msg.content })
    if (opts?.triggerTurn !== false) setTimeout(() => turn("aside", null), 0)
  },
  appendEntry(type, data) {
    log("appendEntry", type, data?.id ?? "", data?.response?.slice?.(0, 60) ?? "")
    if (type === "vox-context-staged") log("STAGED", data.id, JSON.stringify(data.content))
    push({ type: "custom", customType: type, data })
  },
  getSessionName() { return "adr050-session" },
}
const ctx = {
  mode: "tui", agent: { kind: "main" }, cwd: CWD,
  sessionManager: {
    getSessionId: () => SESSION,
    getLeafId: () => branch.at(-1)?.id ?? null,
    getBranch: () => branch,
    getEntries: () => branch,
  },
  ui: { notify(text, level) { log("NOTIFY", level, text) } },
  isIdle: () => idle,
  abort() { log("abort") },
  getAsyncJobSnapshot: () => ({ running: [], recent: [] }),
}
async function emit(ev, event) {
  let result
  for (const fn of handlers.get(ev) ?? []) {
    const r = await fn(event, ctx)
    if (r !== undefined) result = r
  }
  return result
}
let turning = Promise.resolve()
function turn(reason, userText) {
  turning = turning.then(() => runTurn(reason, userText)).catch(e => log("turn-error", String(e)))
  return turning
}
async function runTurn(reason, userText) {
  idle = false
  log("turn-begin", reason, userText ?? "")
  if (userText) {
    const m = { role: "user", content: userText, timestamp: Date.now() }
    push({ type: "message", message: m })
    await emit("message_start", { message: m })
    await emit("message_end", { message: m })
  }
  const r = await emit("before_agent_start", { reason })
  if (r?.message) { log("before_agent_start-returned", r.message.customType, r.message.content); push({ type: "custom_message", customType: r.message.customType, content: r.message.content }) }
  await emit("agent_start", {})
  const messages = branch.filter(e => e.type === "message" || e.type === "custom_message")
    .map(e => e.type === "message" ? e.message : { role: "custom", customType: e.customType, content: e.content })
  const ctxr = await emit("context", { messages })
  const out = ctxr?.messages ?? messages
  const injected = out.filter(m => !messages.includes(m))
  for (const m of injected) {
    const text = typeof m.content === "string" ? m.content : JSON.stringify(m.content)
    const room = text.match(/<vox-room-[0-9a-f]+[^>]*>([\s\S]*?)<\/vox-room-/)
    log("INJECTED", text.replace(/\n/g, "⏎"), "ROOM-PART:", room ? room[1].trim().replace(/\n/g, "⏎") : "(none)")
  }
  if (!injected.length) log("context", `no injection (${out.length} msgs)`)
  await emit("before_provider_request", { payload: { messages: out } })
  const hold = process.env.RCA_HOLD_FILE
  const armed = hold && !userText && reason === "aside" && injected.length && existsSync(hold + ".arm")
  if (hold && ((userText && userText.startsWith("hold")) || armed)) {
    log("hold-begin", hold)
    while (!existsSync(hold)) await new Promise(r => setTimeout(r, 5))
    try { unlinkSync(hold) } catch {}
    log("hold-end")
  }
  const a = { role: "assistant", content: [{ type: "text", text: "ok (" + (userText ?? reason) + ")" }], timestamp: Date.now(), stopReason: (userText?.startsWith("undecided") || (hold && existsSync(hold + ".undecided"))) ? "error" : "stop" }
  await emit("message_start", { message: a })
  await emit("message_end", { message: a })
  push({ type: "message", message: a })
  await emit("agent_end", { willContinue: false, awaitingAsyncWork: false })
  idle = true
  log("turn-end", reason)
  if (armed && process.env.RCA_STOP_AFTER_ASIDE_DECISION === "1") process.kill(process.pid, "SIGSTOP")
}

const vox = (await import(pathToFileURL(extPath))).default
vox(pi)
log("extension-loaded", extPath)
await emit("session_start", {}, ctx)
log("session_start-done")

const rl = createInterface({ input: process.stdin })
rl.on("line", async line => {
  const [cmd, ...rest] = line.split(" ")
  if (cmd === "turn") await turn("prompt", rest.join(" "))
  else if (cmd === "quit") { await emit("session_shutdown", {}); log("shutdown-done"); process.exit(0) }
  else if (cmd === "branch") log("branch", branch.map(e => e.type + ":" + (e.customType ?? e.message?.role ?? "")))
  else log("unknown-command", line)
})
