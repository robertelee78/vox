// The shipped OpenCode plugin, hosted the way OpenCode 2.x hosts it, with no model and no
// OpenCode (V030-21). Used by `room_text_cannot_close_the_opencode_fence_proof.rs` and
// `a_codex_and_an_opencode_session_are_mirrored_and_driven_proof.rs`.
//
//   node opencode_plugin_host.mjs <plugin.mjs> <session id>
//
// It loads the plugin `vox agent plugin opencode` printed and gives it what OpenCode 2.x gives
// a plugin: the plugin context (`{id, setup}` is how 2.x loads it) — its `session.hook` domains,
// its `event.subscribe` stream, and its own session/permission domains, which is how a wake
// arrives and how the plugin's driven calls reach OpenCode. Then it reads one command per line
// on stdin and answers each with one JSON line on stdout:
//
//   turn <text>   a user message typed as <text>: the plugin's `session` `context` hook runs
//                 on it, and the answer is what the model would be given, `{"kind":"turn","text":…}`
//   wake <secs>   wait for `vox daemon` to relay a wake through the plugin's socket, as a
//                 driven `session.prompt` call; OpenCode then runs the context hook on the
//                 relayed prompt, and so does this: `{"kind":"wake","relayed":…,"text":…}`,
//                 or `{"kind":"no-wake"}` past <secs>
//   notice <secs> take the same wake without starting its turn yet, as a busy OpenCode can do;
//                 the room remains unread until a later `turn` or `wake`.
//   event <json>  one event of OpenCode 2.x's bus (`{type, data}`), as the plugin's
//                 `event.subscribe` stream delivers it: `{"kind":"event"}` once it settled
//   title <text>  the session's title as OpenCode holds it, from now on: what the plugin
//                 reads with `ctx.session.get` (a read, not counted among `calls`):
//                 `{"kind":"title"}`
//   calls <secs> <n>
//                 wait until the plugin has made at least <n> calls on OpenCode's session
//                 domain, and answer all of them: `{"kind":"calls","calls":[{method,input}…]}`
//
// Anything the host itself cannot do is `{"kind":"apparatus","error":…}`.

import { readFileSync } from "node:fs"
import { createInterface } from "node:readline"
import { pathToFileURL } from "node:url"

const [pluginPath, session] = process.argv.slice(2)
// OpenCode's own argv, as the plugin sees it inside OpenCode, when the proof names one
// (`STANDIN_ARGV`, JSON): the host is then that OpenCode process to the plugin.
if (process.env.STANDIN_ARGV) process.argv = JSON.parse(process.env.STANDIN_ARGV)

function say(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n")
}

const prompts = []
let waiting = null
// The notices a hosted client receiver submitted (`VOX_PROOF_NOTICES`): the daemon's wake
// reaching the client, which alone submits it (ADR-020 RA7). One JSON line each:
// {"session":…,"text":…,"metadata":{…}}. The offset tracks what this host has taken.
let noticesPath = process.env.VOX_PROOF_NOTICES ?? null
let noticesAt = 0
const notices = []
function takeNotices() {
  if (!noticesPath) return
  let text
  try {
    text = readFileSync(noticesPath, "utf8")
  } catch {
    return
  }
  const lines = text.split("\n")
  if (lines.length && lines[lines.length - 1] === "") lines.pop()
  for (; noticesAt < lines.length; noticesAt += 1) {
    try {
      const record = JSON.parse(lines[noticesAt])
      if (record && typeof record.text === "string") notices.push(record)
    } catch {}
  }
}
function arrival() {
  if (prompts.length) {
    return { text: prompts.shift().text, metadata: null }
  }
  if (notices.length) {
    const notice = notices.shift()
    return { text: notice.text, metadata: notice.metadata ?? null }
  }
  return null
}
// The plugin's calls on OpenCode's own domains, made in process; each is answered as OpenCode
// answers a call it takes.
const calls = []
let callWaiting = null
// The session's title as OpenCode holds it (`title`), or none.
let title = null
// One registered hook per domain name, as `ctx.session.hook` installed it.
const hooks = {}
// The events fed to the plugin's `event.subscribe` stream, and the pump's wake.
const events = []
let eventPushed = null
const register = (domain) => async (name, callback) => {
  hooks[domain + "." + name] = callback
  return { dispose: () => { delete hooks[domain + "." + name] } }
}
const note = (method, input) => {
  calls.push({ method, input: JSON.parse(JSON.stringify(input ?? {})) })
  if (callWaiting) callWaiting()
  return Promise.resolve({})
}
const ctx = {
  location: { directory: process.cwd() },
  session: {
    hook: register("session"),
    // A read of the session: its info, as OpenCode answers it. Not a call the plugin made on
    // the session's behalf, so not among `calls`.
    get: (input) =>
      Promise.resolve({
        data: { id: input.sessionID, parentID: null, ...(title ? { title } : {}) },
      }),
    // OpenCode takes the prompt and answers; the turn it starts runs the context hook after.
    prompt: (input) => {
      const text = input?.text?.text ?? ""
      prompts.push({ session: input.sessionID, text })
      if (waiting) waiting()
      return note("session.prompt", input)
    },
    interrupt: (input) => note("session.interrupt", input),
    update: (input) => note("session.update", input),
    compact: (input) => note("session.compact", input),
    command: (input) => note("session.command", input),
  },
  permission: {
    hook: register("permission"),
    reply: (input) => note("permission.reply", input),
  },
  tool: { hook: register("tool") },
  shell: { hook: register("shell") },
  event: {
    // OpenCode's event stream: each fed event is delivered once, in order.
    subscribe: () => ({
      async *[Symbol.asyncIterator]() {
        for (;;) {
          while (events.length) {
            const event = events.shift()
            yield event
          }
          await new Promise((resolve) => { eventPushed = resolve })
          eventPushed = null
        }
      },
    }),
  },
}

let turnSequence = 0
async function turn(text, metadata = null) {
  turnSequence += 1
  const messageID = `msg_vox_host_${turnSequence}`
  const message = {
    id: messageID,
    role: "user",
    content: [{ type: "text", text }],
    ...(metadata ? { metadata } : {}),
  }
  await hooks["session.context"]({
    sessionID: session,
    model: { providerID: "host", modelID: "host" },
    system: [],
    messages: [message],
    options: {},
    agent: "host",
    tools: {},
  })
  return message.content[0].text
}

let cleanup
try {
  const mod = await import(pathToFileURL(pluginPath).href)
  if (!mod?.default || typeof mod.default !== "object"
    || typeof mod.default.id !== "string" || typeof mod.default.setup !== "function") {
    throw new Error("the plugin does not export a 2.x {id, setup} definition")
  }
  cleanup = await mod.default.setup(ctx)
} catch (e) {
  say({ kind: "apparatus", error: "loading the plugin: " + e })
  process.exit(2)
}

const lines = createInterface({ input: process.stdin })
for await (const line of lines) {
  const [cmd, ...rest] = line.split(" ")
  const arg = rest.join(" ")
  try {
    if (cmd === "turn") {
      say({ kind: "turn", text: await turn(arg) })
    } else if (cmd === "wake" || cmd === "notice") {
      let next = null
      const deadline = Date.now() + Number(arg) * 1000
      while (Date.now() < deadline) {
        takeNotices()
        next = arrival()
        if (next) break
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, 50)
          waiting = () => {
            clearTimeout(timer)
            resolve()
          }
        })
        waiting = null
      }
      if (!next) say({ kind: "no-wake" })
      else say({ kind: "wake", relayed: next.text,
        ...(cmd === "wake" ? { text: await turn(next.text, next.metadata) } : {}) })
    } else if (cmd === "title") {
      title = arg
      say({ kind: "title" })
    } else if (cmd === "event") {
      // The fed event is delivered by the stream the plugin pumps; the short settle holds
      // this answer until the pump has taken the event, while the proofs that depend on
      // its effects poll for those effects with their own deadlines.
      events.push(JSON.parse(arg))
      if (eventPushed) eventPushed()
      await new Promise((resolve) => setTimeout(resolve, 100))
      say({ kind: "event" })
    } else if (cmd === "calls") {
      const [secs, n] = arg.split(" ").map(Number)
      const deadline = Date.now() + secs * 1000
      while (calls.length < n && Date.now() < deadline) {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, Math.max(0, deadline - Date.now()))
          callWaiting = () => {
            clearTimeout(timer)
            resolve()
          }
        })
        callWaiting = null
      }
      say({ kind: "calls", calls })
    } else {
      say({ kind: "apparatus", error: "unknown command " + JSON.stringify(cmd) })
    }
  } catch (e) {
    say({ kind: "apparatus", error: String(e) })
  }
}
try { await cleanup?.() } catch {}
process.exit(0)
