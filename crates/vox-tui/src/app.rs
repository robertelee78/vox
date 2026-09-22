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
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

use crate::live::LiveCore;
use crate::state::{idle_lock_due, Action, PromptKind, UiState};
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

/// Run this profile's node **without a terminal**, so agent sessions can attach
/// (ADR-020 §12).
///
/// This exists because neither of the other two ways to run a node can serve an
/// unattended host:
///
/// - [`run_live`] is the TUI. It is the only other caller of `node::ipc::bind`, it
///   needs a TTY to prompt for the passphrase, and per ADR-015 it **locks the node
///   on SIGHUP** — so detaching it from a terminal defeats it by design.
/// - [`run_node`] is an anchor. It serves the board and carries circuits, but it is
///   headless in the other sense: no identity is unlocked, it holds no room and it
///   can read nothing.
///
/// So an agent on a server had no node to attach to, which contradicted this ADR's
/// own premise that sessions may be on "n-count remote hosts".
///
/// ## Passphrases
///
/// Read from **stdin**, not from the environment: an environment variable is
/// visible in `/proc/<pid>/environ` to anything running as the same user, and in
/// `ps -E` on some systems. Not from argv either, for the same reason.
///
/// The format is one passphrase per line, because a room needs **two** keys, not
/// one — ADR-010's double lock means unlocking the identity does not open a room:
///
/// ```text
/// <identity passphrase>
/// <room id or unique prefix> <that room's passphrase>
/// <room id or unique prefix> <that room's passphrase>
/// ```
///
/// A room line splits at its **first space**, so a room passphrase may contain
/// spaces — which the generated ones do. With no room lines the daemon unlocks the
/// identity and holds no open room, which is enough to serve `vox room list` and
/// nothing else.
///
/// `--passphrase-file` reads the same format from a file, for a service manager
/// that prefers one.
///
/// # Errors
/// If the runtime cannot start, the node cannot spawn, the passphrase is unreadable
/// or wrong, a named room is unknown or its passphrase is refused, or the control
/// socket cannot be bound — the last of which **is** fatal here, unlike in the TUI,
/// because serving that socket is this command's entire purpose.
/// How often a daemon re-reads its anchor configuration and re-resolves it.
///
/// Short enough that a moved anchor is followed within a minute, long enough that it is
/// not a resolver load: the node only acts when something actually changed, because
/// merging an address it already holds is a no-op.
const ANCHOR_REFRESH: std::time::Duration = std::time::Duration::from_secs(30);

pub fn run_daemon(
    paths: Paths,
    listen: std::net::SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    anchor_specs: Vec<String>,
    passphrase_file: Option<std::path::PathBuf>,
) -> Result<(), AppError> {
    use std::io::Read as _;

    let raw = match &passphrase_file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| AppError::Usage(format!("reading {}: {e}", path.display())))?,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| AppError::Usage(format!("reading passphrases on stdin: {e}")))?;
            buf
        }
    };
    let mut lines = raw.lines();
    // Only the line ending is stripped. A passphrase may legitimately begin or end
    // with a space, so nothing else is trimmed.
    let identity = lines.next().unwrap_or_default().trim_end_matches('\r');
    if identity.is_empty() {
        return Err(AppError::Usage(
            "no identity passphrase. Pipe it in (`echo … | vox daemon`), or pass \
             --passphrase-file."
                .into(),
        ));
    }
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let cfg = vox_core::node::actor::NodeConfig::new()
        .bind(vox_core::node::actor::Bind::Addr(listen))
        .anchors(anchors);
    let node = rt.block_on(async { Node::spawn_config(paths.clone(), cfg) })?;

    rt.block_on(async {
        let outcome = node
            .apply(NodeCommand::Unlock {
                passphrase: Secret::new(identity.as_bytes().to_vec()),
            })
            .await;
        if !outcome.is_done() {
            return Err(AppError::Usage(format!(
                "could not unlock this profile's identity: {outcome:?}"
            )));
        }
        // Then the second lock. `vox room post|read|board` all need the room OPEN,
        // not merely known — a daemon that unlocked the identity and stopped there
        // would answer `room list` and refuse everything else, which is the defect
        // this proof found the first time it ran.
        for line in &rooms {
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
                if !outcome.is_done() {
                    return Err(AppError::Usage(format!(
                        "could not open that room: {outcome:?}"
                    )));
                }
                continue;
            }
            // A passphrase, tried everywhere still closed. A room it does not open stays
            // closed — the state it was already in — so this cannot lose anything, and it
            // is no kind of oracle: whoever piped this in already holds the identity
            // passphrase.
            let closed: Vec<_> = node
                .view()
                .channels
                .iter()
                .filter(|c| !c.open)
                .map(|c| c.channel_id)
                .collect();
            for channel_id in closed {
                let _ = node
                    .apply(NodeCommand::OpenChannel {
                        channel_id,
                        passphrase: Secret::new(line.as_bytes().to_vec()),
                    })
                    .await;
            }
        }
        // Say what is actually held, by id, because the names cannot be shown for the
        // rooms that stayed closed and a silent daemon is how this went unnoticed.
        let view = node.view();
        let (open, shut) = (
            view.channels.iter().filter(|c| c.open).count(),
            view.channels.iter().filter(|c| !c.open).count(),
        );
        if shut > 0 {
            eprintln!(
                "vox daemon: {open} room(s) open, {shut} still closed — a closed room \
                 answers nothing but `room list`"
            );
        }
        Ok(())
    })?;

    // **Follow the anchor when it moves.**
    //
    // An anchor spec may name a host rather than an address, and the reason it may is
    // that a home connection's address changes whenever the ISP decides — the point
    // being that a person should not have to re-issue it to every client. Resolution
    // happened once, when this process read its configuration, so a daemon that runs for
    // days held whatever the name meant at startup and redialled that address for ever.
    // The failure attributes badly: the anchor is up, the name is right, and the client
    // says only that it cannot reach a peer.
    //
    // So re-read the configuration and re-resolve every spec on a timer, and hand the
    // node anything new. Re-reading is what makes this provable without a DNS record to
    // move: the same `merge_anchor_spec` runs again, so a name is resolved again whether
    // it was the file or the record that changed.
    {
        let node = node.clone();
        let paths = paths.clone();
        let specs = anchor_specs.clone();
        rt.spawn(async move {
            loop {
                tokio::time::sleep(ANCHOR_REFRESH).await;
                let mut set = vox_core::nat::bootstrap::BootstrapSet::new();
                if vox_core::node::link::merge_anchors_file(&mut set, &paths.anchors_file())
                    .is_err()
                {
                    continue;
                }
                for spec in &specs {
                    let _ = vox_core::node::link::merge_anchor_spec(&mut set, spec);
                }
                if !set.is_empty() {
                    let _ = node
                        .apply(vox_core::node::api::NodeCommand::AddAnchors { anchors: set })
                        .await;
                }
            }
        });
    }

    // Unlike the TUI, a failure here is fatal: serving this socket is the whole job.
    let _ipc = rt
        .block_on(async { vox_core::node::ipc::bind(node.clone(), &paths) })
        .map_err(|e| AppError::Usage(format!("control socket: {e}")))?;

    let fp = node
        .view()
        .identity
        .map(|i| vox_core::node::link::b32_encode(&i.fingerprint))
        .unwrap_or_default();
    println!("vox daemon: identity {fp}");
    println!(
        "vox daemon: control socket {}",
        paths.socket_file().display()
    );
    for room in node.view().open_channels {
        println!(
            "vox daemon: holding room {} open",
            vox_core::node::link::b32_encode(&room.channel_id)
        );
    }

    // **The interrupt path (ADR-020 §6).** The daemon is the only thing that sees
    // every entry as it lands and also knows which local sessions exist, so it is
    // where "addressed and urgent" turns into a wake. The rule is deliberately
    // narrow: a message interrupts only if it names this agent *and* is marked
    // urgent. Everything else waits for the next turn, because an interrupt that
    // fires on everything is a queue with worse manners.
    {
        let node = node.clone();
        let paths = paths.clone();
        rt.spawn(async move {
            let mut events = node.subscribe();
            while let Some(item) = events.next().await {
                let vox_core::node::actor::EventStreamItem::Event(
                    vox_core::node::api::NodeEvent::NewEntry { channel_id, row },
                ) = item
                else {
                    continue;
                };
                let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
                    continue;
                };
                let room = vox_core::node::link::b32_encode(&channel_id);
                for session in crate::wake::registered(&paths) {
                    if session.room != room || session.name.is_empty() {
                        continue;
                    }
                    if !envelope.may_interrupt(&session.name) {
                        continue;
                    }
                    let text = format!(
                        "Urgent message for you in Vox room {}:\n\n{}",
                        &room[..12.min(room.len())],
                        envelope.body.trim()
                    );
                    if let Err(e) = crate::wake::wake(&session, &text).await {
                        // Reported, never fatal: an agent that cannot be interrupted
                        // still reads the message on its next turn, which is the
                        // whole point of queueing always.
                        eprintln!(
                            "vox daemon: could not interrupt session {}: {e}",
                            session.session
                        );
                    }
                }
            }
        });
    }

    rt.block_on(async {
        // **SIGHUP must be explicitly ignored, not merely left unhandled.** Its
        // default disposition is to terminate the process, so "we do not handle it"
        // means "it kills us" — which the proof caught on its first run. The TUI
        // locks on SIGHUP because a terminal going away means the operator walked
        // off. A daemon has no terminal to lose, and SIGHUP is what a service
        // manager sends to ask for a reload, so dying on it would make this
        // unusable. Registering a stream for it replaces the default action; the
        // task then drains it forever and does nothing.
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(mut hup) => {
                    tokio::spawn(async move {
                        while hup.recv().await.is_some() {
                            // Deliberately nothing. See above.
                        }
                    });
                }
                // Worth saying out loud rather than panicking: the daemon still
                // works, but it will now die if anything sends it a SIGHUP.
                Err(e) => eprintln!(
                    "vox daemon: could not take over SIGHUP ({e}); a hangup will stop this daemon"
                ),
            }
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(e) => {
                    eprintln!("vox daemon: no SIGTERM handler ({e}); stop it with Ctrl-C");
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        println!("vox daemon: shutting down");
        let _ = node.apply(NodeCommand::Shutdown).await;
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
