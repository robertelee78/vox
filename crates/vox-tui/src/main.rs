//! `vox` — the Vox Lux terminal client entry point (ADR-015).
//!
//! Thin wrapper over the `vox_tui` library: parse the CLI and dispatch. The
//! library holds all testable logic; this binary owns process startup/teardown.

fn main() -> std::process::ExitCode {
    // **For proofs only** (V210-145, #364): Linux's default `kernel.yama.ptrace_scope=1` lets a
    // process be traced only by its ancestors, so the hung-proof watchdog's `gdb` — the test
    // process's child, a sibling of every `vox` it started — cannot attach to one, and a hung
    // proof's dump showed no `vox` stacks. A `vox` built with `test-knobs` lets any process of
    // this user trace it. Not compiled in without that feature: the binary a person installs keeps
    // the kernel's default.
    #[cfg(all(target_os = "linux", feature = "test-knobs"))]
    let _ = rustix::process::set_ptracer(rustix::process::PTracer::Any);
    vox_tui::cli::run()
}
