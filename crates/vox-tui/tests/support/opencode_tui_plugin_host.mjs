// The shipped OpenCode TUI plugin, hosted the way OpenCode 2.x's TUI hosts it, with no model
// and no OpenCode (V030-21). Used by `room_text_cannot_close_the_opencode_fence_proof.rs`.
//
//   node opencode_tui_plugin_host.mjs <tui-plugin.mjs> <session id> <notices.json>
//
// It loads the plugin `vox agent plugin opencode --tui` printed and gives it what OpenCode
// 2.x's TUI gives a TUI plugin: the `{id, setup}` context, whose `client.session.prompt` is
// how a notice is submitted, whose `ui.router.current()` is the same Solid store route (this
// host pins it to the one session it stands for), and whose returned cleanup runs at exit.
// A notice the plugin submits — which is the daemon's wake reaching the client, and only the
// client submitting it (ADR-020 RA7) — is appended to `<notices.json>`, one JSON line:
//
//   {"session":…,"text":…,"metadata":{…}}
//
// which the server-plugin host reads as the prompt the real client would have delivered to
// OpenCode itself. Anything the host itself cannot do is `{"kind":"apparatus","error":…}`
// on stdout, and the host exits 2.

import { appendFileSync } from "node:fs"
import { register } from "node:module"
import { pathToFileURL } from "node:url"

// OpenCode's TUI bundles Solid for its plugins; this host provides the same surface,
// pinned, so the shipped plugin's imports resolve exactly as they do in the TUI.
register(new URL("./opencode-tui-solid-resolve.mjs", import.meta.url))

const [pluginPath, session, noticesPath] = process.argv.slice(2)

function say(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n")
}

if (typeof session !== "string" || !session) {
  say({ kind: "apparatus", error: "no session id" })
  process.exit(2)
}

const submitted = []
const ctx = {
  location: { directory: process.cwd() },
  client: {
    session: {
      // OpenCode takes the prompt and answers; the turn it starts runs the context hook
      // after. This host stands for the client alone, so the notice is delivered to the
      // notices file the server-plugin host reads.
      prompt: (input) => {
        try {
          const text = input?.text?.text ?? ""
          if (typeof text !== "string" || !text.trim()) return Promise.reject(new Error("empty notice"))
          const record = {
            session: input?.sessionID ?? session,
            text,
            metadata: input?.text?.metadata ?? null,
          }
          appendFileSync(noticesPath, JSON.stringify(record) + "\n")
          submitted.push(record.text)
          return Promise.resolve({})
        } catch (e) {
          return Promise.reject(e)
        }
      },
    },
  },
  ui: {
    router: {
      // The same Solid store the TUI's route is: pinned here to the one session this
      // client stands for, as the TUI showing that session's route would be.
      current() {
        return { type: "session", sessionID: session }
      },
    },
  },
}

let cleanup
try {
  const mod = await import(pathToFileURL(pluginPath).href)
  if (!mod?.default || typeof mod.default !== "object"
    || typeof mod.default.id !== "string" || typeof mod.default.setup !== "function") {
    throw new Error("the TUI plugin does not export a 2.x {id, setup} definition")
  }
  cleanup = await mod.default.setup(ctx)
} catch (e) {
  say({ kind: "apparatus", error: "loading the TUI plugin: " + e })
  process.exit(2)
}

// One line per notice the client submitted, said once at exit, so a proof can tell a
// submission that never came from one that came and was not delivered.
process.on("exit", () => {
  try { say({ kind: "client", submitted }) } catch {}
})
try { await cleanup?.() } catch {}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    try { cleanup?.() } catch {}
    process.exit(0)
  })
}
// The receiver stays open for the daemon's wake until the proof ends it; a ref'd timer
// holds the process the way the real TUI's own loop would.
setInterval(() => {}, 1 << 30)
