// The resolve hook for the TUI plugin host: OpenCode's TUI bundles Solid for its plugins,
// so the shipped TUI plugin imports `solid-js` for its reactive route tracking. This host
// stands where the TUI stands, so it provides the same surface — pinned, not reactive: the
// host's one session never changes route, and the plugin's computed runs once over it.
export async function resolve(specifier, context, next) {
  if (specifier === "solid-js") {
    return {
      url: new URL("./opencode-tui-solid-stub.mjs", import.meta.url).href,
      shortCircuit: true,
    }
  }
  return next(specifier, context)
}
