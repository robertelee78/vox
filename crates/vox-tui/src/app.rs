//! The interactive terminal event loop (ADR-015 §"Async runtime", §"At-rest …
//! screen security").
//!
//! Owns the terminal lifecycle and the render/input loop, delegating *all* logic
//! to the tested [`UiState`] state machine and the pure [`crate::ui::render`]. The
//! loop:
//! - enters the **alternate screen** before any draw and leaves it (clearing its
//!   buffer + a best-effort `ESC[3J`) on exit, so decrypted text never lands in the
//!   primary buffer / scrollback (ADR-015 screen-security claim);
//! - restores the terminal on **every** exit path (normal quit, error, and panic
//!   unwind) via a RAII guard whose `Drop` runs best-effort restore;
//! - routes input through [`UiState::on_key`]; navigation is fully live, and a
//!   [`crate::viewmodel::Command`] is handed to the bound [`CoreHandle`].
//!
//! ## Live-core integration seam (honest scope, ADR-015)
//! Producing the [`ViewModel`] from a running embedded node and applying
//! [`Command`]s against the core (identity vault unlock, channel create/join, log
//! append + render-gate, sync) is the [`CoreHandle`] contract. This module ships the
//! complete, terminal-correct shell and the boundary; binding it to a live node is
//! the integration the manual end-to-end verification phase exercises. The shell is
//! runnable today against any [`CoreHandle`] — including [`OfflineCore`], which holds
//! the view and records commands without inventing trust or message state.

use std::io::{self, Stdout, Write};
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::state::{Action, UiState};
use crate::ui::render;
use crate::viewmodel::{Command, CommandStatus, ViewModel};

/// Errors from the terminal loop.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A terminal I/O error (raw mode, alternate screen, draw, or event read).
    #[error("terminal I/O error: {0}")]
    Io(#[from] io::Error),
}

/// The contract the loop uses to talk to the running core: it provides the current
/// [`ViewModel`] to render and consumes [`Command`]s the user issues. A live
/// implementation drives an embedded `vox-core` node; [`OfflineCore`] is the
/// no-network shell binding.
pub trait CoreHandle {
    /// The latest view model to render.
    fn view(&self) -> ViewModel;
    /// Apply a user command; returns a **typed** status to surface (no free text,
    /// so the status channel cannot leak plaintext/secret detail).
    fn apply(&mut self, command: Command) -> CommandStatus;
    /// An optional startup banner surfaced in the status line — used to state
    /// plainly when the client is running without a live node (so an offline shell
    /// is never mistaken for a connected client). `None` for a live core.
    fn startup_notice(&self) -> Option<String> {
        None
    }
}

/// A no-network core binding: renders an empty/seeded view and records commands as
/// status messages without fabricating channels, messages, or trust state. Honest
/// default until a live node is attached (ADR-015 integration seam).
#[derive(Default)]
pub struct OfflineCore {
    view: ViewModel,
}

impl OfflineCore {
    /// A fresh offline core with the given initial view.
    #[must_use]
    pub fn new(view: ViewModel) -> Self {
        Self { view }
    }
}

impl CoreHandle for OfflineCore {
    fn view(&self) -> ViewModel {
        self.view.clone()
    }

    fn apply(&mut self, command: Command) -> CommandStatus {
        // Offline: do not fabricate delivery. Report a bounded, honest status.
        match command {
            Command::CreateChannel { .. } | Command::Join { .. } => CommandStatus::NeedsNode,
            Command::SendText { .. } => CommandStatus::NotConnected,
            Command::Lock => CommandStatus::Locked,
            _ => CommandStatus::Queued,
        }
    }

    fn startup_notice(&self) -> Option<String> {
        Some(
            "offline — no node attached: navigation only. Attach a node to create/join and chat."
                .to_owned(),
        )
    }
}

/// A RAII guard that restores the terminal on **every** exit path — normal return,
/// an error `?`, or a panic unwind (its `Drop` runs during unwinding). Every step
/// is best-effort (a failure in one does not skip the others), so the terminal is
/// never left in raw mode or on the alternate screen with decrypted text visible.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort, in order: leave raw mode, leave the alternate screen, purge
        // scrollback (ESC[3J — best-effort; tmux/screen/script may retain copies,
        // the documented honest limit, ADR-015), restore the cursor.
        let _ = disable_raw_mode();
        let mut out = io::stdout();
        let _ = execute!(out, LeaveAlternateScreen);
        let _ = execute!(
            out,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::Purge)
        );
        let _ = execute!(out, crossterm::cursor::Show);
        let _ = out.flush();
    }
}

/// Run the interactive TUI against `core`. An internal RAII guard restores the
/// terminal on every exit path (including panic).
pub fn run_tui(mut core: impl CoreHandle) -> Result<(), AppError> {
    enable_raw_mode()?;
    // From here on, any return/panic restores the terminal via the guard's Drop.
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    event_loop(&mut terminal, &mut core)
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    core: &mut impl CoreHandle,
) -> Result<(), AppError> {
    let mut ui = UiState::new();
    // Surface any startup notice (e.g. the offline-shell banner) until the user acts.
    ui.status_message = core.startup_notice();
    loop {
        let vm = core.view();
        terminal.draw(|f| render(f, &vm, &ui))?;

        // Poll so the render loop never blocks indefinitely (idle-lock timers and
        // core-pushed updates can be folded in here by the live integration).
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            // Ignore key-release events (crossterm reports both on some platforms).
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match ui.on_key(key, &vm) {
                Action::Quit => return Ok(()),
                Action::Redraw => {}
                Action::Dispatch(cmd) => {
                    ui.status_message = Some(core.apply(cmd).message());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_core_records_commands_without_fabrication() {
        let mut core = OfflineCore::default();
        let status = core.apply(Command::SendText {
            channel_id: [0; 32],
            text: "hi".into(),
        });
        assert_eq!(
            status,
            CommandStatus::NotConnected,
            "offline send is not faked"
        );
        // The view stays empty — no channel/message was invented.
        assert!(core.view().channels.is_empty());
    }

    #[test]
    fn offline_core_lock_is_reported() {
        let mut core = OfflineCore::default();
        assert_eq!(core.apply(Command::Lock), CommandStatus::Locked);
    }

    #[test]
    fn offline_core_announces_itself_at_startup() {
        // The offline shell must state plainly that no node is attached, so it is
        // never mistaken for a connected client.
        let notice = OfflineCore::default().startup_notice().unwrap();
        assert!(notice.contains("offline"));
        assert!(notice.contains("node"));
    }
}
