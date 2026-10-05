//! The interactive terminal event loop and runtime (ADR-015 §"Async runtime",
//! §"At-rest … screen security"; ADR-016 M13.5).
//!
//! ## Runtime shape (ADR-015, ADR-026 S-4)
//! [`run_live`] builds a **multi-threaded tokio runtime** and makes the TUI a **client of the
//! account's daemon**: it hosts no node and holds no node lock. It runs the UI loop on the
//! calling thread as the **blocking crossterm task**: crossterm's event polling is synchronous,
//! so the loop owns the terminal while the daemon connections and the signal handler run on the
//! runtime. The loop reads the latest [`ViewModel`] projection each frame and hands it a
//! [`Command`] per user action through the [`CoreHandle`] boundary ([`DaemonCore`]).
//!
//! ## Screen security (ADR-015)
//! Terminal I/O is behind [`TerminalIo`] so the sequence is **testable**: the
//! alternate screen is entered before any draw and left — with the buffer cleared
//! and a best-effort `ESC[3J` purge — on exit, so decrypted text never lands in the
//! primary buffer / scrollback; the real backend restores the terminal on every
//! exit path (normal return, error, panic unwind) via a RAII guard.
//!
//! ## No lock (ADR-026 N-2, ADR-015 11.2–11.3)
//! There is no lock: a node takes its passphrase once, when it attaches, and its secrets are wiped
//! when it detaches, in the daemon. When the view reports the node not attached, the masked
//! prompt asks for its passphrase and attaches it; a node without an identity opens the
//! create-identity prompt. `SIGHUP`, like `SIGTERM` and `q`, stops the TUI cleanly and does
//! nothing to its node.

use std::io::{self, Stdout, Write};
use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::{Frame, Terminal};
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

use crate::live::DaemonCore;
use crate::state::{Action, PromptKind, UiState};
use crate::ui::render;
use crate::viewmodel::{Command, CommandStatus, ViewModel};

/// Errors from the terminal loop / runtime.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// An I/O error, from anywhere in the CLI — the terminal (raw mode, alternate
    /// screen, draw, event read) but also the updater, the installer and the file
    /// verbs, all of which convert `io::Error` through this `From`.
    ///
    /// It said "terminal I/O error" until 2026-09-22, which was wrong everywhere
    /// except the terminal loop and actively misleading: a Linux `vox update` that
    /// could not execute its downloaded candidate reported a terminal problem to a
    /// person who was not looking at a terminal problem.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The embedded node could not be started (profile/store error).
    #[error("node: {0}")]
    Core(#[from] vox_core::error::Error),
    /// The command cannot be carried out as asked, with a reason for the person —
    /// a room that is not here, an ambiguous id, a capability they do not hold.
    #[error("{0}")]
    Usage(String),
    /// Refused on purpose, with the exit status that says why — so a program can tell
    /// a version refusal (3) or an operation conflict (4) from any other failure
    /// without parsing prose (ADR-021 §5, §6).
    #[error("{message}")]
    Refused {
        /// The process exit status.
        code: u8,
        /// For the person.
        message: String,
    },
}

impl AppError {
    /// The process exit status this error should end the process with.
    #[must_use]
    pub fn exit_code(&self) -> std::process::ExitCode {
        match self {
            AppError::Refused { code, .. } => std::process::ExitCode::from(*code),
            _ => std::process::ExitCode::FAILURE,
        }
    }
}

/// The contract the loop uses to talk to the running core: it provides the current
/// [`ViewModel`] to render and consumes [`Command`]s the user issues. The live
/// implementation is [`DaemonCore`] (a client of the account's daemon); [`OfflineCore`]
/// is the no-node shell used by tests.
/// What the TUI's status line says while creating the identity waits for another
/// vox holding the profile.
pub const WAITING_FOR_PROFILE_TUI: &str =
    "waiting: another vox holds this profile open, and only one at a time may write it — this goes on by itself";

pub trait CoreHandle {
    /// The latest view model to render (may fold in pending core events).
    fn view(&mut self) -> ViewModel;
    /// Apply a user command; returns a **typed** status to surface (no free text,
    /// so the status channel cannot leak plaintext/secret detail).
    fn apply(&mut self, command: Command) -> CommandStatus;
    /// [`CoreHandle::apply`], calling `waiting` if the command has to wait for another vox
    /// holding the profile, so the loop can say so on screen while it waits (V210-100).
    fn apply_noting(&mut self, command: Command, waiting: &mut dyn FnMut()) -> CommandStatus {
        let _ = waiting;
        self.apply(command)
    }
    /// An optional startup banner surfaced in the status line — used to state
    /// plainly when the client is running without a live node (so an offline shell
    /// is never mistaken for a connected client). `None` for a live core.
    fn startup_notice(&self) -> Option<String> {
        None
    }
    /// Why the TUI cannot go on, once it cannot: the daemon it is a client of stopped. The loop
    /// then ends, and the TUI exits non-zero saying so (ADR-026 L-7).
    fn ended(&self) -> Option<String> {
        None
    }
}

/// A no-node core binding: renders an empty/seeded view and records commands as
/// status messages without fabricating channels, messages, or trust state. Used
/// by tests; the binary always runs [`DaemonCore`].
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
    /// [`TerminalIo::poll_key`] for a key going into a secret field (a passphrase), read so that
    /// nothing outlives it but the field itself (see [`CrosstermIo`]'s). Defaults to `poll_key`.
    fn poll_secret_key(&mut self, timeout: Duration) -> io::Result<Option<KeyEvent>> {
        self.poll_key(timeout)
    }
    /// Leave the alternate screen (clearing it), purge scrollback, restore the
    /// terminal. Idempotent; also performed on drop by real backends.
    fn leave(&mut self) -> io::Result<()>;
    /// Whether the process was asked to stop (SIGTERM), so the loop ends as a quit does. The
    /// loop checks it at least every poll.
    fn stop_requested(&self) -> bool {
        false
    }
}

/// The real crossterm/ratatui backend with a RAII restore on every exit path.
pub struct CrosstermIo {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    entered: bool,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CrosstermIo {
    /// A backend over stdout (nothing touches the terminal until `enter`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            terminal: None,
            entered: false,
            stop: std::sync::Arc::default(),
        }
    }

    /// Set to stop the loop as a quit would (see [`TerminalIo::stop_requested`]).
    #[must_use]
    pub fn stop_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.stop)
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
        // Cleared as well: on a terminal without an alternate screen, anything printed before the
        // TUI started (a wait for the profile, V210-100) would otherwise show through.
        execute!(
            stdout,
            EnterAlternateScreen,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
        )?;
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

    fn stop_requested(&self) -> bool {
        self.stop.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// **A passphrase is read past crossterm** (V210-94). crossterm reads the terminal into a
    /// 1024-byte buffer of its own, which it keeps for the life of the process and never clears:
    /// a passphrase typed at the unlock prompt stayed there, whole, after the node locked — and after
    /// a typed `:lock`, all of it but the six bytes `:lock\r` overwrote. Measured through the shipped
    /// binary. While a secret field is being typed this reads the terminal itself, one byte into one
    /// byte of stack, wiped before it returns; crossterm reads nothing meanwhile, so its buffer never
    /// sees a passphrase.
    #[cfg(unix)]
    fn poll_secret_key(&mut self, timeout: Duration) -> io::Result<Option<KeyEvent>> {
        secret_input::poll_key(timeout)
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

/// Reading a key for a secret field straight from the terminal, past crossterm; see
/// [`CrosstermIo::poll_secret_key`].
#[cfg(unix)]
mod secret_input {
    use std::io::{self, IsTerminal as _, Read as _};
    use std::time::{Duration, Instant};

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use zeroize::Zeroize as _;

    /// How long the rest of a multi-byte key (an escape sequence, a UTF-8 character) may take to
    /// arrive once its first byte has: they come in one write.
    const REST_OF_KEY: Duration = Duration::from_millis(30);

    /// The terminal crossterm reads: standard input when it is one, else `/dev/tty`.
    fn tty() -> io::Result<std::fs::File> {
        use std::os::fd::AsFd as _;
        let stdin = io::stdin();
        if stdin.is_terminal() {
            return Ok(std::fs::File::from(stdin.as_fd().try_clone_to_owned()?));
        }
        std::fs::File::options().read(true).open("/dev/tty")
    }

    /// One byte within `wait`, into `b`; `false` if none came.
    fn byte(tty: &mut std::fs::File, b: &mut [u8; 1], wait: Duration) -> io::Result<bool> {
        use std::os::fd::AsFd as _;
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let fd = tty.as_fd();
            let mut fds = [rustix::event::PollFd::new(
                &fd,
                rustix::event::PollFlags::IN,
            )];
            let ts = rustix::event::Timespec::try_from(left).ok();
            match rustix::event::poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Ok(false),
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
            return match tty.read(b) {
                Ok(1) => Ok(true),
                Ok(_) => Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => Err(e),
            };
        }
    }

    /// Wait up to `timeout` for one key, decoded the way crossterm decodes the keys a prompt uses.
    /// An escape sequence (an arrow, a function key) is read whole and ignored.
    pub(super) fn poll_key(timeout: Duration) -> io::Result<Option<KeyEvent>> {
        let mut tty = tty()?;
        let mut b = [0u8; 1];
        let key = (|| -> io::Result<Option<KeyEvent>> {
            if !byte(&mut tty, &mut b, timeout)? {
                return Ok(None);
            }
            let plain = |code| Some(KeyEvent::new(code, KeyModifiers::NONE));
            Ok(match b[0] {
                b'\r' | b'\n' => plain(KeyCode::Enter),
                0x7f | 0x08 => plain(KeyCode::Backspace),
                b'\t' => plain(KeyCode::Tab),
                0x1b => {
                    if !byte(&mut tty, &mut b, REST_OF_KEY)? {
                        return Ok(plain(KeyCode::Esc));
                    }
                    // `ESC [ … final` or `ESC O x`: read to its final byte and drop it.
                    if b[0] == b'[' || b[0] == b'O' {
                        let ss3 = b[0] == b'O';
                        while byte(&mut tty, &mut b, REST_OF_KEY)? {
                            if ss3 || (0x40..=0x7e).contains(&b[0]) {
                                break;
                            }
                        }
                    }
                    None
                }
                c @ 0x00..=0x1f => Some(KeyEvent::new(
                    KeyCode::Char(char::from(c | 0x60)),
                    KeyModifiers::CONTROL,
                )),
                lead => {
                    // UTF-8: the lead byte says how many follow. Assembled in a stack array wiped
                    // below, like `b`.
                    let len = match lead {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf7 => 4,
                        _ => return Ok(None),
                    };
                    let mut buf = [0u8; 4];
                    buf[0] = lead;
                    let mut ok = true;
                    for slot in buf.iter_mut().take(len).skip(1) {
                        if !byte(&mut tty, &mut b, REST_OF_KEY)? {
                            ok = false;
                            break;
                        }
                        *slot = b[0];
                    }
                    let c = ok
                        .then(|| std::str::from_utf8(&buf[..len]).ok()?.chars().next())
                        .flatten();
                    buf.zeroize();
                    c.and_then(|c| plain(KeyCode::Char(c)))
                }
            })
        })();
        b.zeroize();
        key
    }
}

/// Run the interactive TUI against `core` on the real terminal.
pub fn run_tui(core: impl CoreHandle) -> Result<(), AppError> {
    run_loop(CrosstermIo::new(), core)
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

/// The addresses of `listening` another machine can dial: none on loopback (`127.0.0.0/8`, `::1`).
fn off_machine(listening: &[String]) -> Vec<String> {
    listening
        .iter()
        .filter(|text| {
            vox_core::nat::multiaddr::Multiaddr::parse(text)
                .ok()
                .and_then(|m| m.socket_addr())
                .is_none_or(|sa| !sa.ip().to_canonical().is_loopback())
        })
        .cloned()
        .collect()
}

/// A signal that asks this process to stop, as `stop_requested` resolves to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopSignal {
    /// Ctrl-C.
    Interrupt,
    /// A service manager's, or `kill`'s.
    Terminate,
    /// The terminal went away: a closed window, a dropped ssh session.
    Hangup,
    /// `Ctrl-\`.
    Quit,
}

impl StopSignal {
    /// Its name, as a person reads it: `SIGTERM`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            StopSignal::Interrupt => "SIGINT",
            StopSignal::Terminate => "SIGTERM",
            StopSignal::Hangup => "SIGHUP",
            StopSignal::Quit => "SIGQUIT",
        }
    }

    /// 128 + the signal's number, as a shell reports a process the signal killed.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            StopSignal::Interrupt => 130,
            StopSignal::Terminate => 143,
            StopSignal::Hangup => 129,
            StopSignal::Quit => 131,
        }
    }
}

/// Resolves when this process is asked to stop: Ctrl-C (SIGINT), SIGTERM (a service manager's stop,
/// `kill`), SIGHUP (its terminal went away) or SIGQUIT (`Ctrl-\`) (V210-85, V210-93), to which one
/// it was. Each is registered when this is called, not when the future is first polled, so a signal
/// that arrives before the caller first waits is not lost; call it once, before the work it races,
/// and keep it.
///
/// **Registering one replaces its default action for the rest of the process**, so only a verb
/// that races this for its whole run may call it: anywhere else, Ctrl-C would stop doing anything.
/// Left to their defaults these ended the process on the spot, saying nothing — for `vox connect`
/// a non-zero exit with an empty stderr (V210-85).
pub(crate) fn stop_requested(verb: &'static str) -> impl std::future::Future<Output = StopSignal> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, Signal, SignalKind};
        let listen = |kind: SignalKind, name: &str| match signal(kind) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("{verb}: no {name} handler ({e})");
                None
            }
        };
        let mut int = listen(SignalKind::interrupt(), "SIGINT");
        let mut term = listen(SignalKind::terminate(), "SIGTERM");
        let mut hup = listen(SignalKind::hangup(), "SIGHUP");
        let mut quit = listen(SignalKind::quit(), "SIGQUIT");
        async fn recv(s: &mut Option<Signal>) {
            match s {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        async move {
            tokio::select! {
                () = recv(&mut int) => StopSignal::Interrupt,
                () = recv(&mut term) => StopSignal::Terminate,
                () = recv(&mut hup) => StopSignal::Hangup,
                () = recv(&mut quit) => StopSignal::Quit,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = verb;
        let interrupted = tokio::signal::ctrl_c();
        async move {
            let _ = interrupted.await;
            StopSignal::Interrupt
        }
    }
}

pub fn run_node(
    paths: Paths,
    listen: std::net::SocketAddr,
    anchor_specs: Vec<String>,
    serve_only: Option<std::collections::BTreeSet<vox_core::hash::Digest32>>,
) -> Result<(), AppError> {
    use vox_core::identity::composite::RootSigner;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // **Every stop signal is a clean stop, taken first** (V210-93, V210-85): SIGINT, SIGTERM, SIGHUP
    // and SIGQUIT, before the lock is waited for.
    let mut interrupted = Box::pin({
        let _in_runtime = rt.enter();
        stop_requested("vox node")
    });
    // Its key, made here when there is none (ADR-026 C-5): what the daemon then attaches.
    let fingerprint = vox_core::node::headless::load_or_create_identity(&paths)?.fingerprint();
    let fp = vox_core::node::link::b32_encode(&fingerprint);
    let account = paths.account();
    let node = crate::client::name_of(&paths)?;
    // **`vox node` is a daemon with one headless node in the anchor role** (ADR-026 N-5), not a
    // process of another kind: it holds the account, serves its socket, and attaches the node.
    let Some(serving) = crate::daemon::take_account(&account, &rt, listen, &anchor_specs)? else {
        return Err(AppError::Refused {
            code: 1,
            message: format!(
                "a vox daemon is already running for {}; attach the anchor to it: vox node \
                 attach {node}",
                account.data_root.display()
            ),
        });
    };
    let router = serving.router.clone();
    router.attach_kept();
    if let Some(creators) = serve_only {
        println!(
            "vox node: serving only rooms made by the {} identit{} this profile trusts",
            creators.len(),
            if creators.len() == 1 { "y" } else { "ies" }
        );
        router.serve_only(&node, creators);
    }
    rt.block_on(router.attach(&node, None, None, Vec::new(), Vec::new()))
        .map_err(|r| AppError::Usage(r.to_string()))?;
    let Some(node) = router.handle_of(&node) else {
        return Err(AppError::Usage(format!(
            "node {node} detached as it attached"
        )));
    };
    // Kept for the anchors file the loop below writes (M17.4).
    let anchors_paths = paths.clone();
    println!("vox node: identity {fp}");
    println!("vox node: control socket {}", account.socket().display());
    let signal = rt.block_on(async {
        // Addresses are discovered on a task after start-up (a route probe and a
        // gateway request); print the anchor specs once they are known, then serve.
        let mut printed: Vec<String> = Vec::new();
        let mut last_state: (usize, usize, usize) = (usize::MAX, 0, 0);
        // What the board actually holds per room, reported when it changes. See below.
        let mut last_board: Vec<String> = Vec::new();
        let mut last_holding: Vec<String> = Vec::new();
        let mut stalls = node.subscribe();
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(500));
        // **One Ctrl-C listener for the whole loop, not one per turn.** A listener sees only
        // signals that arrive after it starts listening, and one made inside the `select!` is
        // dropped whenever the tick wins. A SIGINT delivered in the same turn as a tick — an
        // anchor descheduled past a tick on a loaded box, then signalled — went to a listener
        // that was then dropped, and the anchor served on, deaf to Ctrl-C: 13 of 20 anchors
        // stopped for 1.2 s and signalled never exited.
        //
        // **And not only on Ctrl-C** (V210-93, V210-85): SIGTERM, which a service manager and
        // `kill` send, SIGHUP and SIGQUIT stop it the same way. Left to their defaults they killed
        // it on the spot, closes unsent — SIGQUIT with a core dump — and every peer counted the
        // anchor as connected until it stopped answering.
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
                        // **Elsewhere is another machine** (V210-170, #395): the anchors file above
                        // keeps loopback for clients on this one, but a loopback spec printed for
                        // copying to another machine is one that cannot reach this anchor.
                        // A loopback spec is still printed, apart and said for what it is: a profile on
                        // this machine that reads another anchors file uses it.
                        let elsewhere = off_machine(&listening);
                        let here: Vec<&String> =
                            listening.iter().filter(|a| !elsewhere.contains(a)).collect();
                        if elsewhere.is_empty() {
                            println!(
                                "vox node: clients on this machine need no --anchor. It listens on \
                                 no address another machine can dial."
                            );
                        } else {
                            println!("vox node: clients on this machine need no --anchor. Elsewhere:");
                            for addr in &elsewhere {
                                println!("  {fp}@{addr}");
                            }
                        }
                        if !here.is_empty() {
                            println!(
                                "vox node: on this machine only, for a profile that reads another \
                                 anchors file:"
                            );
                            for addr in here {
                                println!("  {fp}@{addr}");
                            }
                        }
                        printed = listening;
                    }

                    // **An anchor must be able to say how it is.**
                    //
                    // Until this, a `vox node` printed four lines at start-up and then
                    // nothing for the rest of its life. It serves no control socket and
                    // has no status verb, so there was no way — from the box it runs on
                    // or anywhere else — to ask whether it was healthy, how many peers it
                    // held, or whether it was answering at all.
                    //
                    // That is how a real anchor sat wedged for an hour looking perfectly
                    // alive: it accepted nothing, said nothing, and the only signal its
                    // operator had was somebody else reporting they could not reach it.
                    // An always-on process with no observability is one you cannot
                    // operate, and this one exists to be always on.
                    //
                    // It reports on change rather than on a timer, so a healthy quiet
                    // anchor stays quiet and a log is not a heartbeat to scroll past —
                    // and every line is something that actually happened.
                    let view = node.view();
                    let now = (view.connected, view.relaying, view.anchoring.len());
                    if now != last_state {
                        let (peers, circuits, rooms) = now;
                        println!(
                            "vox node: {peers} peer(s) connected, {circuits} circuit(s) \
                             carried, {rooms} room(s) on the board"
                        );
                        last_state = now;
                    }
                    // **How many members of each room this board knows.** The line above counts
                    // rooms, which is the one number that was never wrong. Whether an anchor has
                    // come to know a room's *members* is the fact that decides whether anyone away
                    // from the room can reconcile with them — a board holding a room and one member
                    // of a two-member room is useless in exactly the way that looks like working —
                    // and an operator had no way to see it. It is also unreadable from outside: the
                    // symptom appears on somebody else's node, as a peer that cannot be reached.
                    //
                    // On change, like everything else here, so a settled anchor stays silent.
                    //
                    // **In words** (V210-171, #396): `1m/0p` was read cold as "peers", and the line
                    // exists to be read without the source. The board does not count a room's
                    // entries, so the line says nothing about them rather than imply none.
                    let board: Vec<String> = view
                        .anchoring
                        .iter()
                        .map(|a| {
                            format!(
                                "{}: {} member{}, {} pending",
                                crate::tunnel_cli::short_id_of(&a.channel_id),
                                a.members,
                                if a.members == 1 { "" } else { "s" },
                                a.pending,
                            )
                        })
                        .collect();
                    if board != last_board {
                        println!("vox node: board — {}", board.join("; "));
                        last_board = board;
                    }
                    // **Where the board points each member** (V210-51, #230): the address its live
                    // record names, which is what this board hands anyone asking where that member
                    // is. A process that restarts publishes a new one; a board still naming the old
                    // process's address sends every dial to a socket nobody holds, and nothing else
                    // an operator can read says so. On change, like the rest.
                    let holding: Vec<String> = view
                        .anchoring
                        .iter()
                        .flat_map(|a| {
                            a.holding.iter().map(|(member, addrs)| {
                                format!(
                                    "{} holding {} for {}",
                                    crate::tunnel_cli::short_id_of(&a.channel_id),
                                    addrs.join(" "),
                                    crate::ident::author_id(member)
                                )
                            })
                        })
                        .collect();
                    for line in holding.iter().filter(|l| !last_holding.contains(*l)) {
                        println!("vox node: board — {line}");
                    }
                    last_holding = holding;
                    // Drained without blocking: this arm also has an anchors file to
                    // write, and a status line nobody reads is better than a tick nobody
                    // reaches.
                    // **Everything that explains a failure, not only a stall.** An anchor is the
                    // one node in a room that nobody is watching, and it is the hop a message takes
                    // when two members are never online together. Reporting only `Stalled` meant an
                    // anchor that could not reach a member, or refused a join, or sat on an entry it
                    // had just been handed, said nothing at all — and the room simply looked quiet.
                    while let Some(item) = stalls.try_next() {
                        match item {
                            vox_core::node::actor::EventStreamItem::Event(ev) => match ev {
                                // The one thing an operator cannot see from outside: the node is
                                // up, listening, and answering nobody.
                                vox_core::node::api::NodeEvent::Stalled { what, millis } => {
                                    eprintln!(
                                        "vox node: BUSY {millis}ms — {what} — nobody could be \
                                         answered while this ran"
                                    );
                                }
                                vox_core::node::api::NodeEvent::PeerUnreachable { peer, why } => {
                                    eprintln!(
                                        "vox node: could not reach {} — {why}",
                                        crate::ident::author_id(&peer)
                                    );
                                }
                                vox_core::node::api::NodeEvent::JoinFailed { reason } => {
                                    eprintln!("vox node: a join did not complete — {reason}");
                                }
                                vox_core::node::api::NodeEvent::JoinSteps { joined, steps } => {
                                    eprintln!(
                                        "vox node: join {} — {steps}",
                                        if joined { "got in" } else { "did not get in" }
                                    );
                                }
                                vox_core::node::api::NodeEvent::PublishRefused {
                                    channel_id,
                                    what,
                                    why,
                                } => {
                                    eprintln!(
                                        "vox node: a board would not take {what} for room {} — {why}",
                                        crate::tunnel_cli::short_id_of(&channel_id)
                                    );
                                }
                                vox_core::node::api::NodeEvent::KeyNotTaken {
                                    channel_id,
                                    peer,
                                    why,
                                } => {
                                    eprintln!(
                                        "vox node: {} did not take our key for room {} — {why}; it is sent again",
                                        crate::ident::author_id(&peer),
                                        crate::tunnel_cli::short_id_of(&channel_id)
                                    );
                                }
                                vox_core::node::api::NodeEvent::StillRelayed { peer, reason } => {
                                    eprintln!(
                                        "vox node: still relayed to {} — {reason}",
                                        crate::ident::author_id(&peer)
                                    );
                                }
                                vox_core::node::api::NodeEvent::HandshakesQueued {
                                    waited,
                                    most_waiting,
                                    most_running,
                                    refused,
                                    longest_ms,
                                } => {
                                    eprintln!(
                                        "vox node: {waited} connection attempt(s) waited for a \
                                         handshake slot (at most {most_waiting} at once, the \
                                         longest {longest_ms}ms) while at most {most_running} \
                                         handshake(s) ran; {refused} refused"
                                    );
                                }
                                vox_core::node::api::NodeEvent::ConnectionNote { peer, note } => {
                                    eprintln!(
                                        "vox node: connection to {} — {note}",
                                        crate::ident::author_id(&peer)
                                    );
                                }
                                vox_core::node::api::NodeEvent::NodeNote { note } => {
                                    eprintln!("vox node: {note}");
                                }
                                _ => {}
                            },
                            vox_core::node::actor::EventStreamItem::Lagged(n) => {
                                eprintln!("vox node: fell behind its own events by {n}");
                            }
                        }
                    }
                }
                signal = &mut interrupted => break signal,
            }
        }
    });
    println!("vox node: stopped by {}", signal.name());
    println!("vox node: shutting down");
    let stopped = crate::daemon::stop_daemon(rt, &router, &serving.presence, Some(signal));
    drop(serving);
    stopped
}

/// How long `vox daemon` waits for its node to stop on SIGTERM or Ctrl-C before leaving anyway.
/// A clean stop takes milliseconds; this is for a node stuck waiting on a peer that vanished.
/// It must stay longer than the node's own worst-case stop
/// ([`vox_core::node::actor::STOP_WORST_CASE`], 4.45 s, the sum of the stop's budget), so a stop
/// that waits every one of them out still closes its connections before the daemon leaves.
pub(crate) const SHUTDOWN_PATIENCE: std::time::Duration = std::time::Duration::from_secs(5);
const _: () = assert!(
    vox_core::node::actor::STOP_WORST_CASE.as_millis() + 500 <= SHUTDOWN_PATIENCE.as_millis(),
    "the daemon gives a stop that waits out every bound at least 0.5 s more"
);

/// The test-only variable that shortens [`SHUTDOWN_PATIENCE`], in milliseconds (see
/// [`shutdown_patience`]).
#[cfg(feature = "test-knobs")]
const TEST_SHUTDOWN_PATIENCE_ENV: &str = "VOX_TEST_SHUTDOWN_PATIENCE_MS";

/// [`SHUTDOWN_PATIENCE`], or **shorter**, read from `VOX_TEST_SHUTDOWN_PATIENCE_MS` in a build with
/// the `test-knobs` feature. **Test-only: for proofs; no shipped build reads it** (V210-105). The
/// node's stop is budgeted to fit the real patience, so no real scene runs past it; a proof stages
/// a stop that gives up, and what the daemon then says and how it exits, with a shorter one. It
/// only ever shortens it; unset, empty or unparsable is the real patience.
pub(crate) fn shutdown_patience() -> std::time::Duration {
    #[cfg(feature = "test-knobs")]
    if let Some(ms) = std::env::var(TEST_SHUTDOWN_PATIENCE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return std::time::Duration::from_millis(ms).min(SHUTDOWN_PATIENCE);
    }
    SHUTDOWN_PATIENCE
}

impl AppError {
    /// How a long-running **client** verb (`vox up`, `vox forward`, `vox room tail`) ends when
    /// `signal` stops it (V210-108): `stopped by SIGHUP`, exiting 128 + the signal's number, as a
    /// shell reports a process the signal killed. A server's stop is its normal end, and exits 0.
    #[must_use]
    pub fn stopped_by(signal: StopSignal) -> Self {
        AppError::Refused {
            code: signal.exit_code(),
            message: format!("stopped by {}", signal.name()),
        }
    }
}

/// Print a line on stdout, ignoring a stdout that is gone. After a hangup it can be a terminal that
/// closed, and `println!` panics on a failed write: the stop would end in a panic, not in what the
/// verb says when it stops (V210-108).
pub(crate) fn say(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stdout(), "{line}");
}

/// The identity passphrase `vox daemon` unlocks with, and the room lines that follow it.
pub(crate) type DaemonPassphrases = (zeroize::Zeroizing<String>, Vec<String>);

/// What a start-up wait of `vox daemon` ended with: what it waited for, or a stop.
pub(crate) enum Asked<T> {
    Got(T),
    Stopped(StopSignal),
}

/// `VOX_IDENTITY_PASSPHRASE`, when set: how an agent's harness gives a daemon its identity
/// passphrase (V210-159, decider 2026-10-02, option A). Set to nothing, it gives none on purpose
/// (V030-36).
pub(crate) fn daemon_env_passphrase() -> Option<zeroize::Zeroizing<String>> {
    std::env::var("VOX_IDENTITY_PASSPHRASE")
        .ok()
        .map(zeroize::Zeroizing::new)
}

/// The identity passphrase and the room lines, from the first of: `--passphrase-file`,
/// `VOX_IDENTITY_PASSPHRASE` (the identity alone), the terminal (asked for without echo, and
/// **without waiting for end of input**: one line is the passphrase, V210-153), or stdin that is
/// not a terminal, read to its end. A stop ends any wait for them.
pub(crate) fn daemon_passphrases(
    rt: &tokio::runtime::Runtime,
    stop: &mut std::pin::Pin<Box<impl std::future::Future<Output = StopSignal>>>,
    passphrase_file: Option<std::path::PathBuf>,
) -> Result<Asked<DaemonPassphrases>, AppError> {
    let raw = if let Some(path) = &passphrase_file {
        crate::tunnel_cli::passphrase_file_text(path)?
    } else if let Some(identity) = daemon_env_passphrase() {
        // Said whichever way the passphrase came: an empty one set in the environment goes on
        // without one, and the person is told so here as on every other path (V030-36).
        return Ok(Asked::Got((encouraged(identity), Vec::new())));
    } else if io::IsTerminal::is_terminal(&io::stdin()) {
        return Ok(match ask_without_echo(rt, stop, "identity passphrase") {
            Asked::Got(identity) => match identity? {
                Some(identity) => Asked::Got((encouraged(identity), Vec::new())),
                None => {
                    return Err(AppError::Usage(format!(
                        "{NO_IDENTITY_PASSPHRASE} The terminal's input ended before one was \
                         typed."
                    )))
                }
            },
            Asked::Stopped(signal) => Asked::Stopped(signal),
        });
    } else {
        match read_piped_stdin(rt, stop) {
            // Nothing at all on stdin is no passphrase given; an empty line is an empty one.
            Asked::Got(raw) => given_on_stdin(raw?)?,
            Asked::Stopped(signal) => return Ok(Asked::Stopped(signal)),
        }
    };
    let mut lines = raw.lines();
    // Only the line ending is stripped. A passphrase may legitimately begin or end
    // with a space, so nothing else is trimmed.
    let identity = zeroize::Zeroizing::new(
        lines
            .next()
            .unwrap_or_default()
            .trim_end_matches('\r')
            .to_owned(),
    );
    // `<room> <passphrase>` opens that room. **A line with no space is a passphrase to
    // try against every closed room**, and that form exists because the other one was
    // unusable after a restart.
    //
    // A room's local name lives inside the SEK-sealed manifest, so it cannot be read
    // until the room is open. After a restart every room is closed, so `vox room list`
    // shows them all as `(unnamed)` — correct, the name is the operator's data and must
    // not leak from a locked profile, but it means `mission <pass>` answers "nothing
    // here matches mission". The room *id* does work, and nothing said so; worse,
    // `room list` needs a running node, so learning the ids meant starting a daemon
    // bare, listing, stopping it and starting it again. A person setting up a host for
    // the first time cannot be expected to find that.
    //
    // So: one passphrase on a line of its own opens everything it opens. Nothing is
    // guessed — a room whose passphrase this is not simply stays closed, exactly as it
    // would have.
    let rooms: Vec<String> = lines
        .map(|l| l.trim_end_matches('\r').to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(Asked::Got((encouraged(identity), rooms)))
}

/// `identity`, after one line encouraging a passphrase when it is empty.
///
/// **An empty identity passphrase is accepted** (V030-36, decider 2026-10-02: "passphrase is a
/// good idea, but is technically optional"). It was refused here, so an identity made with none
/// could never be served by a daemon.
fn encouraged(identity: zeroize::Zeroizing<String>) -> zeroize::Zeroizing<String> {
    crate::tunnel_cli::encouraged(identity.as_str(), "identity");
    identity
}

/// What to say when nothing at all was given for the identity passphrase.
const NO_IDENTITY_PASSPHRASE: &str =
    "no identity passphrase. Type it at the terminal (Enter alone \
     gives none), pipe it in (`echo … | vox daemon`; an empty line gives none), set \
     VOX_IDENTITY_PASSPHRASE, or pass --passphrase-file.";

/// Stdin that is not a terminal, read to its end: refused when it held nothing at all. A harness
/// that closes stdin without writing has given nothing, and an identity whose passphrase that is
/// not would only fail later as a wrong one; an empty line is how to give none.
fn given_on_stdin(raw: zeroize::Zeroizing<String>) -> Result<zeroize::Zeroizing<String>, AppError> {
    if raw.is_empty() {
        return Err(AppError::Usage(format!(
            "{NO_IDENTITY_PASSPHRASE} Stdin ended with nothing on it."
        )));
    }
    Ok(raw)
}

/// How long `vox daemon` reads a stdin that is not a terminal before it says what it is waiting
/// for: an agent's harness can leave stdin open and write nothing, and a daemon must not wait
/// there silently (V210-165).
const PIPED_STDIN_NOTICE: Duration = Duration::from_secs(2);

/// Stdin that is not a terminal, read to its end on a blocking thread, racing `stop`.
fn read_piped_stdin(
    rt: &tokio::runtime::Runtime,
    stop: &mut std::pin::Pin<Box<impl std::future::Future<Output = StopSignal>>>,
) -> Asked<Result<zeroize::Zeroizing<String>, AppError>> {
    rt.block_on(async {
        let reading = tokio::task::spawn_blocking(|| {
            use std::io::Read as _;
            let mut buf = zeroize::Zeroizing::new(String::new());
            io::stdin()
                .read_to_string(&mut buf)
                .map(|_| buf)
                .map_err(|e| AppError::Usage(format!("reading passphrases on stdin: {e}")))
        });
        tokio::pin!(reading);
        let notice = tokio::time::sleep(PIPED_STDIN_NOTICE);
        tokio::pin!(notice);
        let mut said = false;
        loop {
            tokio::select! {
                read = &mut reading => {
                    return Asked::Got(read.unwrap_or_else(|e| {
                        Err(AppError::Usage(format!("reading passphrases on stdin: {e}")))
                    }));
                }
                signal = &mut *stop => return Asked::Stopped(signal),
                () = &mut notice, if !said => {
                    said = true;
                    eprintln!(
                        "vox daemon: waiting for stdin to close: the identity passphrase, then \
                         any room lines.\n\
                         \x20      No terminal to ask at. Or set VOX_IDENTITY_PASSPHRASE, or \
                         pass --passphrase-file <path>."
                    );
                }
            }
        }
    })
}

/// How long a prompt whose terminal ended waits for the stop signal that a closed terminal sends.
/// The kernel sends SIGHUP as it ends the read, so it lands within milliseconds; a second covers a
/// loaded machine.
const HANGUP_GRACE: Duration = Duration::from_secs(1);

/// One line typed at the terminal, without echo, racing `stop`; `None` when its input ended with
/// none. A stop leaves the terminal as it was: echo comes back whichever ends the wait.
pub(crate) fn ask_without_echo(
    rt: &tokio::runtime::Runtime,
    stop: &mut std::pin::Pin<Box<impl std::future::Future<Output = StopSignal>>>,
    prompt: &str,
) -> Asked<Result<Option<zeroize::Zeroizing<String>>, AppError>> {
    let _ = write!(io::stderr(), "{prompt}: ");
    let _ = io::stderr().flush();
    let quiet = no_echo::EchoOff::new();
    let asked = rt.block_on(async {
        let reading = tokio::task::spawn_blocking(no_echo::read_line);
        let read = tokio::select! {
            read = reading => read,
            signal = &mut *stop => return Asked::Stopped(signal),
        };
        let read = match read {
            Ok(Ok(Some(line))) => return Asked::Got(Ok(Some(line))),
            // End of input, not an empty line: nothing was typed, which is not an empty
            // passphrase (V030-36).
            Ok(Ok(None)) => Ok(None),
            Ok(Err(e)) => Err(AppError::Usage(format!("reading the terminal: {e}"))),
            Err(e) => Err(AppError::Usage(format!("reading the terminal: {e}"))),
        };
        // **The terminal ended: closed, most likely, and its SIGHUP is on its way** (V210-153).
        // Closing the terminal ends the read and sends the hangup at the same moment, and the
        // read nearly always reaches here first: 11 of 13 real hangups then exited 1 with "no
        // identity passphrase" instead of stopping cleanly. So the stop gets a moment to land.
        // Only a Ctrl-D typed at the prompt, which no signal follows, waits it out.
        tokio::select! {
            signal = &mut *stop => Asked::Stopped(signal),
            () = tokio::time::sleep(HANGUP_GRACE) => Asked::Got(read),
        }
    });
    drop(quiet);
    if matches!(asked, Asked::Stopped(_)) {
        // The prompt's line is left open; the stop's report starts on a line of its own.
        let _ = writeln!(io::stderr());
    }
    asked
}

/// Reading a line at the terminal without echo, and without crossterm's raw mode: the terminal
/// keeps its line editing, and Ctrl-C stays a SIGINT, which the daemon takes as a clean stop.
mod no_echo {
    use std::io;

    /// Echo off on the terminal at stdin until dropped, keeping the newline's echo. Does nothing
    /// where stdin is not a terminal.
    pub(super) struct EchoOff {
        #[cfg(unix)]
        was: Option<rustix::termios::Termios>,
    }

    impl EchoOff {
        pub(super) fn new() -> Self {
            #[cfg(unix)]
            {
                use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
                let stdin = io::stdin();
                let was = tcgetattr(&stdin).ok();
                if let Some(was) = &was {
                    let mut quiet = was.clone();
                    quiet.local_modes.remove(LocalModes::ECHO);
                    quiet.local_modes.insert(LocalModes::ECHONL);
                    let _ = tcsetattr(&stdin, OptionalActions::Now, &quiet);
                }
                Self { was }
            }
            #[cfg(not(unix))]
            Self {}
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            #[cfg(unix)]
            if let Some(was) = &self.was {
                let _ = rustix::termios::tcsetattr(
                    io::stdin(),
                    rustix::termios::OptionalActions::Now,
                    was,
                );
            }
        }
    }

    /// One line from stdin, a byte at a time from the descriptor itself, past std's buffer, so
    /// nothing past it is taken from the terminal and no copy is left behind (V210-94); into a
    /// buffer wiped on drop. `None` when the input ended before a newline: a Ctrl-D, or a
    /// terminal that closed; what came before it is wiped, never taken as a line.
    pub(super) fn read_line() -> io::Result<Option<zeroize::Zeroizing<String>>> {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        let mut b = [0u8; 1];
        loop {
            #[cfg(unix)]
            let read = rustix::io::read(io::stdin(), &mut b).map_err(io::Error::from);
            #[cfg(not(unix))]
            let read = std::io::Read::read(&mut io::stdin(), &mut b);
            match read {
                Ok(0) => {
                    zeroize::Zeroize::zeroize(&mut b);
                    return Ok(None);
                }
                Ok(_) if b[0] == b'\n' => break,
                Ok(_) => bytes.push(b[0]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        zeroize::Zeroize::zeroize(&mut b);
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        String::from_utf8(std::mem::take(&mut *bytes))
            .map(|line| Some(zeroize::Zeroizing::new(line)))
            .map_err(|e| {
                let mut v = e.into_bytes();
                zeroize::Zeroize::zeroize(&mut v);
                io::Error::new(io::ErrorKind::InvalidData, "the line is not UTF-8")
            })
    }
}

/// Open every closed room `line` opens, as `vox daemon` reads a room line: the whole line as a
/// passphrase first, then `<room> <passphrase>`.
pub(crate) async fn open_rooms_by_line(node: &vox_core::node::actor::NodeHandle, line: &str) {
    // **Each line is resolved, not parsed.** The obvious split — `<room> <pass>`
    // on the first space — is ambiguous the moment a passphrase contains a
    // space, and passphrases contain spaces: this file already notes that one
    // may legitimately begin or end with one. A first version of this shipped
    // that split and read the passphrase "channel passphrase" as room "channel",
    // passphrase "passphrase", so the room never opened and the daemon refused
    // to start. Found by a proof using an ordinary passphrase.
    //
    // So: if the first word names a room this profile holds, the rest is that
    // room's passphrase. Otherwise the whole line is a passphrase, tried against
    // every room still closed. Nothing new to learn, and no line that a person
    // would reasonably write is read as the other thing.
    // **Try the whole line as a passphrase FIRST.** The `<room> <pass>` form is
    // still supported below, but it can no longer win by accident.
    //
    // The previous version split on the first space and resolved the prefix as a
    // room id — and `resolve_prefix` takes a *prefix*, so a single letter names a
    // room whenever exactly one id starts with it. A profile holding one room
    // called `asmu2miy723t` therefore read the passphrase `a room passphrase` as
    // room `a`, passphrase `room passphrase`, failed, and **refused to start**.
    // Any passphrase beginning "a ", "the ", "my " hits this; in English most do.
    //
    // That is the same defect the note below already describes, one layer in: the
    // split was made unambiguous against a *full* id and then handed a prefix.
    // Trying the line as a passphrase first costs nothing — a room it does not
    // open stays closed, which is the state it was already in — and a genuine
    // `<room> <pass>` line cannot open anything as a whole-line passphrase,
    // because it has the room id in front of it. So each form still works and
    // neither can be mistaken for the other.
    let closed_now: Vec<_> = node
        .view()
        .channels
        .iter()
        .filter(|c| !c.open)
        .map(|c| c.channel_id)
        .collect();
    let mut opened_by_line = false;
    // What refused the line, per room: said if it opened nothing (#412), never dropped.
    let mut refused: Vec<(vox_core::hash::Digest32, String)> = Vec::new();
    for channel_id in closed_now {
        let outcome = node
            .apply(NodeCommand::OpenChannel {
                channel_id,
                passphrase: Secret::new(line.as_bytes().to_vec()),
            })
            .await;
        if outcome.is_done() {
            opened_by_line = true;
        } else {
            refused.push((channel_id, outcome.to_string()));
        }
    }
    if opened_by_line {
        return;
    }
    let ids: Vec<_> = node.view().channels.iter().map(|c| c.channel_id).collect();
    let named = line.split_once(' ').and_then(|(prefix, pass)| {
        crate::tunnel_cli::resolve_prefix(prefix, &ids)
            .ok()
            .map(|id| (id, pass.to_owned()))
    });
    if let Some((channel_id, pass)) = named {
        let outcome = node
            .apply(NodeCommand::OpenChannel {
                channel_id,
                passphrase: Secret::new(pass.as_bytes().to_vec()),
            })
            .await;
        if outcome.is_done() {
            return;
        }
        // **Say so; do not exit.** This branch used to `return Err(..)`, which
        // killed the daemon over one bad room line — and `7ff0f56` claimed to have
        // fixed that while leaving this return in place. The case that proves it
        // is narrow and is exactly the one that was never run: a line whose first
        // word *does* prefix a room id but whose remainder is the wrong
        // passphrase. A line that resolves nothing takes the whole-line path
        // below, which never had a fatal return, which is why four verified cases
        // all passed and the claim was still false.
        //
        // A room that did not open stays closed, which is the state it was already
        // in, and the summary at the end of this loop names every room still shut.
        // An operator who mistyped one passphrase wants the other rooms served and
        // a line telling them which one failed — not a process that refuses to
        // start.
        eprintln!("vox daemon: could not open that room: {outcome}");
        return;
    }
    // Neither form opened anything. Nothing to undo — a room this did not open stays closed —
    // and what refused the line is said for each room it was tried on (#412): a line that opened
    // nothing with no word left a person giving the right passphrase to a room that could not
    // open, and no way to tell.
    if refused.is_empty() {
        eprintln!("vox daemon: that line opened no room: no room here is closed");
    }
    for (channel_id, why) in refused {
        eprintln!(
            "vox daemon: that line did not open room {}: {}",
            vox_core::node::link::b32_encode(&channel_id)
                .chars()
                .take(12)
                .collect::<String>(),
            why.lines().next().unwrap_or_default()
        );
    }
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
    // The account's file, not this node's own (ADR-026 F-2): every node on this machine reads
    // it unless it keeps an anchors file of its own, so each of them reaches its anchor unasked.
    let path = paths.config_dir.join(vox_core::node::paths::ANCHORS_FILE);
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
    account: vox_core::node::paths::Account,
    node: Option<String>,
    listen: std::net::SocketAddr,
    anchors: Vec<String>,
) -> Result<(), AppError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // The daemon first, before the TUI takes the screen, so a daemon that will not start is said
    // on the terminal (ADR-026 S-2).
    rt.block_on(crate::daemon_client::ensure_daemon(
        &account, listen, &anchors,
    ))?;
    // The node it acts as (C-3): named, else the only one attached, else the only one on disk, else
    // `default` for a data root with none, whose identity the TUI makes.
    let node = crate::client::resolve_node(node.as_deref(), &account, true)
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let stop = tokio_util::sync::CancellationToken::new();
    let core = DaemonCore::new(rt.handle().clone(), account, node, anchors, stop.clone())?;
    let io = CrosstermIo::new();
    #[cfg(unix)]
    {
        // **SIGTERM and SIGHUP stop the TUI as `q` does** (V210-93, ADR-026 S-4): the terminal is
        // restored and the connections to the daemon close. The node is the daemon's: it is left
        // as it is, attached for as long as anything holds it. Left to their defaults these killed
        // the process with the terminal left raw. A wait on the daemon is given up at once (the
        // TUI waited out an attach before it stopped: 9.5 s, measured).
        for kind in [
            tokio::signal::unix::SignalKind::terminate(),
            tokio::signal::unix::SignalKind::hangup(),
        ] {
            let flag = io.stop_flag();
            let stop = stop.clone();
            let signal = {
                let _in_rt = rt.enter();
                tokio::signal::unix::signal(kind)
            };
            if let Ok(mut signal) = signal {
                rt.spawn(async move {
                    if signal.recv().await.is_some() {
                        flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        stop.cancel();
                    }
                });
            }
        }
    }
    let result = run_loop(io, core);
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}

/// The loop over an abstract terminal (the testable core of [`run_tui`]).
pub fn run_loop(mut io: impl TerminalIo, mut core: impl CoreHandle) -> Result<(), AppError> {
    io.enter()?;
    let result = event_loop(&mut io, &mut core);
    io.leave()?;
    result
}

fn event_loop(io: &mut impl TerminalIo, core: &mut impl CoreHandle) -> Result<(), AppError> {
    let mut ui = UiState::new();
    // Surface any startup notice (e.g. the offline-shell banner) until the user acts.
    ui.status_message = core.startup_notice();
    let mut was_attached: Option<bool> = None;
    loop {
        if io.stop_requested() {
            return Ok(());
        }
        let vm = core.view();
        // The daemon it is a client of stopped: nothing here can go on (ADR-026 L-7).
        if let Some(why) = core.ended() {
            return Err(AppError::Usage(why));
        }
        ui.settle(&vm);

        // Onboarding / attach prompts: open once per transition, never on top of another modal.
        if ui.mode.is_normal() {
            if !vm.has_identity && was_attached.is_none() {
                ui.start_prompt(PromptKind::CreateIdentity, None);
            } else if !vm.attached && vm.has_identity && was_attached != Some(false) {
                ui.start_prompt(PromptKind::Attach, None);
            }
        }
        was_attached = Some(vm.attached);

        io.draw(&mut |f| render(f, &vm, &mut ui))?;

        // Poll so the render loop never blocks indefinitely (daemon updates are folded in each
        // tick). A passphrase is read past the terminal library (V210-94): see `poll_secret_key`.
        let key = if ui.typing_a_secret() {
            io.poll_secret_key(Duration::from_millis(250))?
        } else {
            io.poll_key(Duration::from_millis(250))?
        };
        let Some(key) = key else {
            continue;
        };
        match ui.on_key(key, &vm) {
            Action::Quit => return Ok(()),
            Action::Redraw => {}
            Action::Dispatch(cmd) => {
                // **Waiting is said in the status line** (V210-100), never on stderr: stderr is
                // this terminal, and a line written there lands inside the screen.
                let status = core.apply_noting(cmd, &mut || {
                    ui.status_message = Some(WAITING_FOR_PROFILE_TUI.into());
                    let _ = io.draw(&mut |f| render(f, &vm, &mut ui));
                });
                ui.status_message = Some(status.message());
            }
        }
    }
}
