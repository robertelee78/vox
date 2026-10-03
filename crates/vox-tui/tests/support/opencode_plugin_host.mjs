// The shipped OpenCode plugin, hosted the way OpenCode hosts it, with no model and no OpenCode
// (V030-21). Used by `room_text_cannot_close_the_opencode_fence_proof.rs`.
//
//   node opencode_plugin_host.mjs <plugin.mjs> <session id>
//
// It loads the plugin `vox agent plugin opencode` printed and gives it what OpenCode gives a
// plugin: Bun's `$` (here, the same calls made with `node:child_process`, so the real `vox agent
// hook` runs) and a client whose `session.promptAsync` is how a wake arrives. Then it reads one
// command per line on stdin and answers each with one JSON line on stdout:
//
//   turn <text>   a user message typed as <text>: the plugin's `chat.message` runs on it, and
//                 the answer is what the model would be given, `{"kind":"turn","text":…}`
//   wake <secs>   wait for `vox daemon` to relay a wake through the plugin's socket; OpenCode
//                 then runs `chat.message` on the relayed prompt, and so does this:
//                 `{"kind":"wake","relayed":…,"text":…}`, or `{"kind":"no-wake"}` past <secs>
//
// Anything the host itself cannot do is `{"kind":"apparatus","error":…}`.

import { spawn } from "node:child_process"
import { createInterface } from "node:readline"
import { pathToFileURL } from "node:url"

const [pluginPath, session] = process.argv.slice(2)

function say(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n")
}

// Bun's `$` as the plugin uses it: `` $`${bin} agent hook … ${flags}`.env(e).quiet().nothrow() ``,
// awaited for `{ stdout, exitCode }`. Each interpolated value is one argument, an array is several,
// and the literal text between them is split on whitespace, as Bun's shell does.
function $(strings, ...values) {
  const argv = []
  strings.forEach((lit, i) => {
    argv.push(...lit.split(/\s+/).filter(Boolean))
    if (i < values.length) {
      const v = values[i]
      if (Array.isArray(v)) argv.push(...v.map(String))
      else argv.push(String(v))
    }
  })
  let env = process.env
  const cmd = {
    env(e) {
      env = e
      return cmd
    },
    quiet() {
      return cmd
    },
    nothrow() {
      return cmd
    },
    then(resolve, reject) {
      const child = spawn(argv[0], argv.slice(1), { env, stdio: ["ignore", "pipe", "inherit"] })
      const out = []
      child.stdout.on("data", (b) => out.push(b))
      child.on("error", (e) => resolve({ stdout: Buffer.alloc(0), exitCode: 127, error: e }))
      child.on("close", (code) => resolve({ stdout: Buffer.concat(out), exitCode: code ?? -1 }))
      return undefined
    },
  }
  return cmd
}

const prompts = []
let waiting = null
const client = {
  session: {
    // OpenCode takes the prompt and answers 2xx; the turn it starts runs afterwards.
    async promptAsync({ path, body }) {
      const text = body?.parts?.[0]?.text ?? ""
      prompts.push({ session: path?.id, text })
      if (waiting) waiting()
      return { response: { status: 200 } }
    },
  },
}

async function turn(hooks, text) {
  const output = { message: { sessionID: session }, parts: [{ type: "text", text }] }
  await hooks["chat.message"]({ sessionID: session }, output)
  return output.parts[0].text
}

let hooks
try {
  const mod = await import(pathToFileURL(pluginPath).href)
  hooks = await mod.default({ $, client })
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
      say({ kind: "turn", text: await turn(hooks, arg) })
    } else if (cmd === "wake") {
      if (!prompts.length) {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, Number(arg) * 1000)
          waiting = () => {
            clearTimeout(timer)
            resolve()
          }
        })
        waiting = null
      }
      const p = prompts.shift()
      if (!p) say({ kind: "no-wake" })
      else say({ kind: "wake", relayed: p.text, text: await turn(hooks, p.text) })
    } else {
      say({ kind: "apparatus", error: "unknown command " + JSON.stringify(cmd) })
    }
  } catch (e) {
    say({ kind: "apparatus", error: String(e) })
  }
}
process.exit(0)
