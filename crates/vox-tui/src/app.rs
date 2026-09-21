//! The interactive terminal event loop and runtime (ADR-015 §"Async runtime",
//! §"At-rest … screen security"; ADR-016 M13.5).
//!
//! ## Runtime shape (ADR-015)
//! [`run_live`] builds a **multi-threaded tokio runtime**, spawns the embedded
//! `vox-core` node on it, and runs the UI loop on the calling thread as the
//! **blocking crossterm task**: crossterm's event polling is synchronous, so the
//! loop owns the terminal while the node's actor and the signal handler run on
//! the runtime. A `CancellationToken` stops the auxiliary tasks and the node is
//! shut down (locking everything) on every exit path. The loop reads the node's
//! latest [`ViewModel`] projection each frame and hands it a [`Command`] per user
//! action through the [`CoreHandle`] boundary.
//!
//! ## Screen security (ADR-015)
//! Terminal I/O is behind [`TerminalIo`] so the sequence is **testable**: the
//! alternate screen is entered before any draw and left — with the buffer cleared
//! and a best-effort `ESC[3J` purge — on exit, so decrypted text never lands in the
//! primary buffer / scrollback; the real backend restores the terminal on every
//! exit path (normal return, error, panic unwind) via a RAII guard.
//!
//! ## Locking (ADR-015)
//! `:lock`, the idle timer ([`crate::state::IDLE_LOCK_SECS`]) and `SIGHUP` all
//! lock the node (every SEK and the signer are wiped). When the view reports
//! `locked`, the masked unlock prompt opens; a profile without an identity opens
//! the create-identity prompt at startup.

use std::io::{self, Stdout, Write};
use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::{Frame, Terminal};
use tokio_util::sync::CancellationToken;
use vox_core::node::actor::Node;
use vox_core::node::api::NodeCommand;
use vox_core::node::paths::Paths;

use crate::live::LiveCore;
use crate::state::{idle_lock_due, Action, PromptKind, UiState};
use crate::ui::render;
use crate::viewmodel::{Command, CommandStatus, ViewModel};

/// Errors from the terminal loop / runtime.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A terminal I/O error (raw mode, alternate screen, draw, or event read).
    #[error("terminal I/O error: {0}")]
    Io(#[from] io::Error),
    /// The embedded node could not be started (profile/store error).
    #[error("node: {0}")]
    Core(#[from] vox_core::error::Error),
    /// The command cannot be carried out as asked, with a reason for the person —
    /// a room that is not here, an ambiguous id, a capability they do not hold.
    #[error("{0}")]
    Usage(String),
}

/// The contract the loop uses to talk to the running core: it provides the current
/// [`ViewModel`] to render and consumes [`Command`]s the user issues. The live
/// implementation is [`LiveCore`] (an embedded `vox-core` node); [`OfflineCore`]
/// is the no-node shell used by tests.
pub trait CoreHandle {
    /// The latest view model to render (may fold in pending core events).
    fn view(&mut self) -> ViewModel;
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

/// A no-node core binding: renders an empty/seeded view and records commands as
/// status messages without fabricating channels, messages, or trust state. Used
/// by tests; the binary always runs [`LiveCore`].
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
    fn view(&mut self) -> ViewModel {
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

/// Terminal I/O as the loop sees it, so the screen-security sequence is testable.
pub trait TerminalIo {
    /// Enter raw mode and the alternate screen. Must precede any [`TerminalIo::draw`].
    fn enter(&mut self) -> io::Result<()>;
    /// Draw one frame.
    fn draw(&mut self, render: &mut dyn FnMut(&mut Frame)) -> io::Result<()>;
    /// Wait up to `timeout` for a key press (release events are filtered).
    fn poll_key(&mut self, timeout: Duration) -> io::Result<Option<KeyEvent>>;
    /// Leave the alternate screen (clearing it), purge scrollback, restore the
    /// terminal. Idempotent; also performed on drop by real backends.
    fn leave(&mut self) -> io::Result<()>;
}

/// The real crossterm/ratatui backend with a RAII restore on every exit path.
pub struct CrosstermIo {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    entered: bool,
}

impl CrosstermIo {
    /// A backend over stdout (nothing touches the terminal until `enter`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            terminal: None,
            entered: false,
        }
    }
}

impl Default for CrosstermIo {
    fn default() -> Self {
        Self::new()
    }
}

fn restore_terminal() {
    // Best-effort, in order: leave raw mode, leave the alternate screen, purge
    // scrollback (ESC[3J — best-effort; tmux/screen/script may retain copies, the
    // documented honest limit, ADR-015), restore the cursor.
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

impl TerminalIo for CrosstermIo {
    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        self.entered = true;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        self.terminal = Some(Terminal::new(CrosstermBackend::new(stdout))?);
        Ok(())
    }

    fn draw(&mut self, render: &mut dyn FnMut(&mut Frame)) -> io::Result<()> {
        let Some(t) = self.terminal.as_mut() else {
            return Err(io::Error::other("draw before enter"));
        };
        t.draw(|f| render(f))?;
        Ok(())
    }

    fn poll_key(&mut self, timeout: Duration) -> io::Result<Option<KeyEvent>> {
        if !event::poll(timeout)? {
            return Ok(None);
        }
        match event::read()? {
            // Ignore key-release events (crossterm reports both on some platforms).
            Event::Key(key) if key.kind != KeyEventKind::Release => Ok(Some(key)),
            _ => Ok(None),
        }
    }

    fn leave(&mut self) -> io::Result<()> {
        if self.entered {
            self.entered = false;
            self.terminal = None;
            restore_terminal();
        }
        Ok(())
    }
}

impl Drop for CrosstermIo {
    fn drop(&mut self) {
        // Runs on every exit path, including panic unwind.
        let _ = self.leave();
    }
}

/// A wall-clock source for the idle-lock timer (seconds).
pub type Clock = Box<dyn Fn() -> u64>;

fn system_clock() -> Clock {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Run the interactive TUI against `core` on the real terminal.
pub fn run_tui(core: impl CoreHandle) -> Result<(), AppError> {
    run_loop(CrosstermIo::new(), core, system_clock())
}

/// Run the full client: runtime + embedded node + terminal loop, for `paths`.
///
/// `listen` is where the node accepts peers; it is what invite links advertise, so it
/// must be an address peers can reach (see the `--listen` flag).
/// Run the headless anchor (`vox node`, ADR-016 M15.2a) until interrupted.
///
/// No terminal, no vault, no rooms: the node comes up as its file-backed identity,
/// prints what a client should be given as `--anchor` once it knows its addresses,
/// and serves. Ctrl-C shuts it down cleanly (closing connections, deleting any
/// permanent port mapping it took).
/// Keep only the advertised addresses a client could actually dial.
///
/// A node bound to the wildcard advertises `0.0.0.0` (or `::`), which names every local
/// interface to the *kernel* and nothing at all to a peer. It is not an error in the
/// advertised set — the ADR-012 ladder composes it from what the socket reports — but it
/// must never reach an operator as something to paste into `--anchor`.
fn dialable(listening: Vec<String>) -> Vec<String> {
    listening
        .into_iter()
        .filter(|text| {
            vox_core::nat::multiaddr::Multiaddr::parse(text)
                .ok()
                .and_then(|m| m.socket_addr())
                .is_none_or(|sa| !sa.ip().is_unspecified())
        })
        .collect()
}

pub fn run_node(
    paths: Paths,
    listen: std::net::SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
) -> Result<(), AppError> {
    use vox_core::identity::composite::RootSigner;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let signer = vox_core::node::headless::load_or_create_identity(&paths)?;
    let fingerprint = signer.fingerprint();
    let cfg = vox_core::node::actor::NodeConfig::new()
        .bind(vox_core::node::actor::Bind::Addr(listen))
        .anchors(anchors)
        .headless(signer)
        .anchor_logs(true);
    // Kept for the anchors file the loop below writes (M17.4); the node takes its own clone.
    let anchors_paths = paths.clone();
    let node = rt.block_on(async { Node::spawn_config(paths, cfg) })?;
    let fp = vox_core::node::link::b32_encode(&fingerprint);
    println!("vox node: identity {fp}");
    rt.block_on(async {
        // Addresses are discovered on a task after start-up (a route probe and a
        // gateway request); print the anchor specs once they are known, then serve.
        let mut printed: Vec<String> = Vec::new();
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = ticks.tick() => {
                    // A wildcard bind advertises `0.0.0.0`, which is a *bind* address and
                    // not one any client can dial. Printing it as an `--anchor` spec hands
                    // the operator a string guaranteed not to work.
                    let listening = dialable(node.view().listening);
                    if listening != printed && !listening.is_empty() {
                        // Written, not only printed (ADR-017 decision 7, M17.4). A client
                        // on this machine then needs no `--anchor` at all, which was the
                        // point: pasting a 52-character fingerprint and a multiaddr into
                        // every command was the second-worst step in the flow.
                        match write_anchors_file(&anchors_paths, &fp, &listening) {
                            Ok(path) => println!("vox node: wrote {}", path.display()),
                            // Not fatal. An anchor that serves but could not write a
                            // convenience file is still an anchor, and the operator can
                            // paste the specs below.
                            Err(e) => eprintln!("vox node: could not write the anchors file ({e})"),
                        }
                        println!("vox node: clients on this machine need no --anchor. Elsewhere:");
                        for addr in &listening {
                            println!("  {fp}@{addr}");
                        }
                        printed = listening;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("vox node: shutting down");
                    let _ = node.apply(NodeCommand::Shutdown).await;
                    break;
                }
            }
        }
    });
    Ok(())
}

/// Write this anchor's own specs into the profile's anchors file (ADR-017 decision 7, M17.4),
/// returning the path written.
///
/// Rewritten whole on every change rather than appended to, so a restart on a new port does not
/// leave a stale line behind that a client would waste a dial on. Written to a temporary file and
/// renamed, so a reader never sees a half-written file.
///
/// The file carries no secret — an anchor spec is a public identity and a public address — so it is
/// ordinary configuration, and a person may edit it to add anchors on other machines.
fn write_anchors_file(
    paths: &Paths,
    fp: &str,
    listening: &[String],
) -> std::io::Result<std::path::PathBuf> {
    use std::fmt::Write as _;
    let path = paths.anchors_file();
    let mut body = String::from(
        "# Written by `vox node`. Anchors this profile publishes to, reads from and reaches\n\
         # peers through: one <fingerprint>@<multiaddr> per line. Add anchors on other\n\
         # machines here; `--anchor` on a command merges with this file rather than\n\
         # replacing it. Rewritten whole whenever this node's addresses change.\n",
    );
    // `listening` is already multiaddr text, filtered by `dialable` so a wildcard bind's
    // `0.0.0.0` — a bind address no peer can dial — never reaches the file.
    for addr in listening {
        let _ = writeln!(body, "{fp}@{addr}");
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn run_live(
    paths: Paths,
    listen: std::net::SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
) -> Result<(), AppError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let cfg = vox_core::node::actor::NodeConfig::new()
        .bind(vox_core::node::actor::Bind::Addr(listen))
        .anchors(anchors);
    let node = rt.block_on(async { Node::spawn_config(paths.clone(), cfg) })?;
    // The ADR-020 control socket, so agent sessions on this machine can attach to
    // this node rather than each running one of their own. Held for the life of
    // the client: dropping it stops accepting and unlinks the path.
    //
    // A failure here is reported and not fatal. The socket is an extra surface,
    // and a client that cannot offer it should still be a client — refusing to
    // start the TUI because another feature could not bind would be the wrong
    // trade.
    let _ipc = match rt.block_on(async { vox_core::node::ipc::bind(node.clone(), &paths) }) {
        Ok(server) => Some(server),
        Err(e) => {
            eprintln!("vox: control socket unavailable ({e}); `vox room` will not attach");
            None
        }
    };
    let cancel = CancellationToken::new();
    #[cfg(unix)]
    {
        // SIGHUP (terminal went away) locks the node (ADR-015).
        let n = node.clone();
        let c = cancel.clone();
        rt.spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut hup) = signal(SignalKind::hangup()) else {
                return;
            };
            loop {
                tokio::select! {
                    _ = hup.recv() => { let _ = n.apply(NodeCommand::Lock).await; }
                    () = c.cancelled() => break,
                }
            }
        });
    }
    let core = LiveCore::new(node.clone(), rt.handle().clone());
    let result = run_loop(CrosstermIo::new(), core, system_clock());
    cancel.cancel();
    // Shutdown locks (wipes every SEK and the signer) before the process exits.
    let _ = rt.block_on(node.apply(NodeCommand::Shutdown));
    result
}

/// The loop over an abstract terminal (the testable core of [`run_tui`]).
pub fn run_loop(
    mut io: impl TerminalIo,
    mut core: impl CoreHandle,
    clock: Clock,
) -> Result<(), AppError> {
    io.enter()?;
    let result = event_loop(&mut io, &mut core, &clock);
    io.leave()?;
    result
}

fn event_loop(
    io: &mut impl TerminalIo,
    core: &mut impl CoreHandle,
    clock: &Clock,
) -> Result<(), AppError> {
    let mut ui = UiState::new();
    // Surface any startup notice (e.g. the offline-shell banner) until the user acts.
    ui.status_message = core.startup_notice();
    let mut last_input = clock();
    let mut was_locked: Option<bool> = None;
    loop {
        let vm = core.view();

        // Onboarding / re-auth prompts: open once per transition, never on top of
        // another modal.
        if ui.mode.is_normal() {
            if !vm.has_identity && was_locked.is_none() {
                ui.start_prompt(PromptKind::CreateIdentity, None);
            } else if vm.locked && vm.has_identity && was_locked != Some(true) {
                ui.start_prompt(PromptKind::Unlock, None);
            }
        }
        was_locked = Some(vm.locked);

        io.draw(&mut |f| render(f, &vm, &ui))?;

        // Idle lock (ADR-015): lock the node after IDLE_LOCK_SECS without input.
        let now = clock();
        if !vm.locked && vm.has_identity && idle_lock_due(last_input, now) {
            ui.status_message = Some(core.apply(Command::Lock).message());
            last_input = now;
            continue;
        }

        // Poll so the render loop never blocks indefinitely (core-pushed updates
        // and the idle timer are folded in each tick).
        let Some(key) = io.poll_key(Duration::from_millis(250))? else {
            continue;
        };
        last_input = clock();
        match ui.on_key(key, &vm) {
            Action::Quit => return Ok(()),
            Action::Redraw => {}
            Action::Dispatch(cmd) => {
                ui.status_message = Some(core.apply(cmd).message());
            }
        }
    }
}
