//! `vox` — the Vox Lux terminal client entry point (ADR-015).
//!
//! Thin wrapper over the `vox_tui` library: parse the CLI and dispatch. The
//! library holds all testable logic; this binary owns process startup/teardown.

fn main() -> std::process::ExitCode {
    vox_tui::cli::run()
}
