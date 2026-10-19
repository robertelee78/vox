// The Solid surface the shipped TUI plugin uses, as OpenCode's TUI provides it, pinned to
// one call: this host's route never changes, so a computed runs once over it and a root's
// disposal is kept for the plugin's cleanup. Resolved by `opencode-tui-solid-resolve.mjs`.

export function createRoot(fn) {
  const disposers = []
  const dispose = () => {
    while (disposers.length) {
      const disposeOne = disposers.pop()
      try { disposeOne() } catch {}
    }
  }
  try {
    return fn(dispose)
  } catch (e) {
    dispose()
    throw e
  }
}

export function createComputed(fn) {
  try { fn() } catch {}
}

export function onCleanup(fn) {
  return () => {
    try { fn() } catch {}
  }
}
