//! `vox daemon`: the account's one daemon (ADR-026 §1, §5).
//!
//! It takes the stop signals first, then the account lock (D-1), moves an older layout into
//! `nodes/` under that lock (F-3), serves the account socket (C-1) through its [`Router`],
//! attaches the `--keep` nodes in the background (L-4), and then the foreground node, if one
//! resolves (C-3), with the passphrases and the lines `vox daemon` has always printed. A stop
//! signal detaches every node and ends it (S-1).
//!
//! When another daemon holds the lock, a `vox daemon` that names a node hands the node to it
//! (D-1): it attaches the node there as a held session, stays in the foreground until a stop
//! signal, and then lets the node go (unless `--keep`). One started by a client
//! ([`crate::daemon_client`]) exits once it has no node and no client (L-8).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::actor::Bind;
use vox_core::node::daemonipc::{
    AttachMode, DaemonClient, DaemonFrame, DaemonRequest, KeepSource, Refusal, UseNode,
};
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::paths::{Account, NodeName, DEFAULT_PROFILE};
use zeroize::Zeroizing;

use crate::app::{
    ask_without_echo, daemon_env_passphrase, daemon_passphrases, open_rooms_by_line, say,
    shutdown_patience, stop_requested, AppError, Asked, SHUTDOWN_PATIENCE,
};
use crate::cli::DaemonArgs;
use crate::host::{Defaults, Router};

/// How long an auto-started daemon lingers with no node and no client before it exits (L-8).
const IDLE_LINGER: Duration = Duration::from_secs(1);

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
/// From `--passphrase-file`, else `VOX_IDENTITY_PASSPHRASE` (the identity's alone: how an agent's
/// harness starts one, decider 2026-10-02), else asked for at the terminal without echo, else
/// read from stdin to its end. Never from argv, which every process on the machine can read.
///
/// The format of a file or of stdin is one passphrase per line, because a room needs **two** keys, not
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
pub fn run(args: &DaemonArgs) -> Result<(), AppError> {
    // Refused before anything is read or unlocked: a metrics endpoint the network can
    // reach names every peer and room this node talks to (PRD-001 R38).
    if let Some(addr) = args.metrics {
        if !addr.ip().is_loopback() {
            return Err(AppError::Usage(format!(
                "--metrics {addr}: the metrics endpoint binds loopback only (127.0.0.1 or \
                 ::1); it names every peer and room this node talks to"
            )));
        }
    }
    let account = Account::of(
        args.profile.data_dir.as_deref(),
        args.profile.config_dir.as_deref(),
    )
    .map_err(|e| AppError::Usage(e.to_string()))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    if args.detach {
        let started = rt.block_on(crate::daemon_client::ensure_daemon(
            &account,
            args.profile.listen,
            &args.profile.anchors,
        ))?;
        println!(
            "vox daemon: {} in the background; its log is {}",
            match started {
                crate::daemon_client::Daemon::Started => "started",
                crate::daemon_client::Daemon::Running => "already running",
            },
            account.log_file().display()
        );
        return Ok(());
    }
    if args.as_detached {
        // Its own session: the terminal or harness that started the client can close without
        // its hangup reaching the daemon.
        let _ = rustix::process::setsid();
    }
    // **Every stop signal is a clean stop, taken from the start** (V210-108, V210-153): SIGINT,
    // SIGTERM, SIGHUP and SIGQUIT. Taken first, before the lock or any passphrase: a daemon closed
    // with its terminal while it waited there died on the default action.
    let mut stop = Box::pin({
        let _in_runtime = rt.enter();
        stop_requested("vox daemon")
    });
    let named = named_node(args)?;
    let Some(lock) = account
        .try_lock()
        .map_err(|e| AppError::Usage(e.to_string()))?
    else {
        return already_running(args, &account, rt, &mut stop, named);
    };
    let lock = Arc::new(Mutex::new(lock));
    write_pid(&lock);
    // Under the lock, once: an older layout moves into `nodes/` (F-3).
    let report = vox_core::node::layout::migrate_held(&account, named.as_ref())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    for (from, node) in &report.moved {
        eprintln!("vox daemon: moved {} to node {node}", from.display());
    }
    for (node, anchor) in &report.split {
        eprintln!("vox daemon: node {node}'s anchor key is now node {anchor}");
    }

    let mut anchors = vox_core::nat::bootstrap::BootstrapSet::new();
    for spec in &args.profile.anchors {
        if !spec.trim().is_empty() {
            vox_core::node::link::merge_anchor_spec(&mut anchors, spec)
                .map_err(|e| AppError::Usage(e.to_string()))?;
        }
    }
    // **The daemon's one presence** (ADR-026 D-3, ADR-012 N-41–N-45): one socket and endpoint
    // for every node it attaches, on the data root's kept port (`.daemon/port`), with the relay
    // limits of `.daemon/config`.
    let limits = vox_core::node::circuitstream::RelayLimits::read(&account.daemon_config_file())
        .map_err(AppError::Usage)?;
    let presence = rt
        .block_on(async {
            let (shared, moved) = vox_core::node::presence::NetPresence::bind_kept(
                args.profile.listen,
                &account.port_file(),
                None,
            )?;
            if let Some(moved) = moved {
                eprintln!("vox daemon: {moved}");
            }
            Ok::<_, vox_core::error::Error>(vox_core::node::presence::NetPresence::start(shared))
        })
        .map_err(|e| AppError::Usage(format!("listen on {}: {e}", args.profile.listen)))?;
    presence.ledger().set_limits(limits);
    let router = Router::new(
        account.clone(),
        rt.handle().clone(),
        Defaults {
            bind: shared_presence(&presence),
            anchors,
            anchor_specs: args.profile.anchors.clone(),
            listen: args.profile.listen.to_string(),
            patience: shutdown_patience(),
            // Every client speaks to the account socket (#406): no node serves one of its own.
            node_sockets: false,
        },
    );
    // Unlike the TUI, a failure here is fatal: serving this socket is the whole job.
    let _socket = rt
        .block_on(async {
            vox_core::node::ipc::bind_account(Arc::new(router.clone()), account.socket())
        })
        .map_err(|e| AppError::Usage(format!("control socket: {e}")))?;
    router.attach_kept();

    if let Some(addr) = args.metrics {
        let listener = rt
            .block_on(vox_core::node::status::bind_metrics(addr))
            .map_err(|e| AppError::Usage(e.to_string()))?;
        let bound = listener.local_addr().map_err(AppError::Io)?;
        let r = router.clone();
        rt.spawn(vox_core::node::status::serve_metrics_for(
            listener,
            Some(router.metrics()),
            move || r.attached_handles(),
        ));
        println!("vox daemon: metrics http://{bound}/metrics");
    }

    // The foreground node.
    let foreground = if args.as_detached {
        None
    } else {
        resolve(&account, named)
    };
    match &foreground {
        Some(node) => {
            if let Some(signal) = attach_foreground(args, &account, &rt, &mut stop, &router, node)?
            {
                // A stop while it asked for a passphrase ends it at once, as it always has.
                let _ = rt.block_on(tokio::time::timeout(shutdown_patience(), router.stop_all()));
                rt.shutdown_background();
                say(format_args!("vox daemon: stopped by {}", signal.name()));
                return Ok(());
            }
        }
        None if !args.as_detached => {
            let nodes = account.nodes_on_disk();
            eprintln!(
                "vox daemon: {} node(s) here and none named, so none is attached: name one with \
                 --node ({})",
                nodes.len(),
                nodes
                    .iter()
                    .map(NodeName::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("vox daemon: control socket {}", account.socket().display());
        }
        None => println!("vox daemon: control socket {}", account.socket().display()),
    }

    let signal = rt.block_on(async {
        let idle = async {
            if !args.as_detached {
                return std::future::pending::<()>().await;
            }
            let mut since: Option<Instant> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Its data root deleted under it: nothing it serves exists any more.
                if !account.daemon_dir().exists() {
                    return;
                }
                if router.idle() {
                    let t = *since.get_or_insert_with(Instant::now);
                    if t.elapsed() >= IDLE_LINGER {
                        return;
                    }
                } else {
                    since = None;
                }
            }
        };
        tokio::select! {
            signal = &mut stop => Some(signal),
            () = router.stop_asked() => None,
            () = idle => None,
        }
    });
    stop_daemon(rt, &router, &presence, signal)
}

/// The node `vox daemon` was named (C-3's first step): `--node` / `VOX_NODE`, or a `--profile`
/// other than the default while the clients still pass it.
fn named_node(args: &DaemonArgs) -> Result<Option<NodeName>, AppError> {
    args.node
        .clone()
        .map(|n| NodeName::parse(&n).map_err(|e| AppError::Usage(e.to_string())))
        .transpose()
}

/// The foreground node (C-3): the named one, else the only node on disk, else `default` when
/// there is none (its attach then says to make an identity), else none.
fn resolve(account: &Account, named: Option<NodeName>) -> Option<NodeName> {
    if named.is_some() {
        return named;
    }
    let mut on_disk = account.nodes_on_disk();
    match on_disk.len() {
        0 => NodeName::parse(DEFAULT_PROFILE).ok(),
        1 => on_disk.pop(),
        _ => None,
    }
}

/// Where each node binds: **the daemon's one presence**, for every node (ADR-026 D-3). Every
/// attached node is answered at the same ip:port, by the identity exchange; none binds a socket of
/// its own.
fn shared_presence(presence: &Arc<vox_core::node::presence::NetPresence>) -> crate::host::BindFor {
    let presence = Arc::clone(presence);
    Arc::new(move |_: &NodeName| Some(Bind::Shared(Arc::clone(&presence))))
}

/// Write this daemon's pid into the lock file, so a person (or a proof) can see which process
/// holds it.
fn write_pid(lock: &Arc<Mutex<std::fs::File>>) {
    use std::io::{Seek as _, Write as _};
    let mut f = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = f.set_len(0);
    let _ = f.seek(io::SeekFrom::Start(0));
    let _ = writeln!(f, "{}", std::process::id());
}

/// The passphrase source `--keep` records: the passphrase file, or none.
fn keep_source(args: &DaemonArgs) -> Option<KeepSource> {
    args.keep.then(|| match &args.passphrase_file {
        Some(p) => KeepSource::File(std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())),
        None => KeepSource::None,
    })
}

/// Attach the foreground node with its passphrases and say what `vox daemon` has always said.
/// `Some(signal)` when a stop came while it asked for a passphrase.
fn attach_foreground(
    args: &DaemonArgs,
    account: &Account,
    rt: &tokio::runtime::Runtime,
    stop: &mut std::pin::Pin<Box<impl std::future::Future<Output = crate::app::StopSignal>>>,
    router: &Router,
    node: &NodeName,
) -> Result<Option<crate::app::StopSignal>, AppError> {
    let interactive = args.passphrase_file.is_none()
        && daemon_env_passphrase().is_none()
        && io::IsTerminal::is_terminal(&io::stdin());
    let (identity, rooms) = match daemon_passphrases(rt, stop, args.passphrase_file.clone())? {
        Asked::Got(got) => got,
        Asked::Stopped(signal) => return Ok(Some(signal)),
    };
    let rooms: Vec<Zeroizing<String>> = rooms.into_iter().map(Zeroizing::new).collect();
    let attached =
        rt.block_on(router.attach(node, Some(identity), keep_source(args), rooms, Vec::new()));
    if let Err(r) = attached {
        return Err(AppError::Usage(refusal_words(&r, account, node)));
    }
    let Some(handle) = router.handle_of(node) else {
        return Err(AppError::Usage(format!(
            "node {node} detached as it attached"
        )));
    };
    // **At a terminal, the rooms still closed are asked for** (V210-153), one passphrase at a
    // time, as a piped line would give them; an empty one starts the daemon without them.
    if interactive {
        loop {
            let shut = handle.view().channels.iter().filter(|c| !c.open).count();
            if shut == 0 {
                break;
            }
            let prompt = format!(
                "passphrase for a closed room ({shut} closed; Enter to start without them)"
            );
            let line = match ask_without_echo(rt, stop, &prompt) {
                Asked::Got(line) => line?.unwrap_or_default(),
                Asked::Stopped(signal) => return Ok(Some(signal)),
            };
            if line.is_empty() {
                break;
            }
            rt.block_on(open_rooms_by_line(&handle, &line));
        }
    }
    say_held(&handle, account);
    Ok(None)
}

/// The lines a started daemon prints: what is held, by id, because the names cannot be shown for
/// rooms that stayed closed and a silent daemon is how that went unnoticed.
fn say_held(handle: &vox_core::node::actor::NodeHandle, account: &Account) {
    let view = handle.view();
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
    let fp = view
        .identity
        .map(|i| vox_core::node::link::b32_encode(&i.fingerprint))
        .unwrap_or_default();
    println!("vox daemon: identity {fp}");
    println!("vox daemon: control socket {}", account.socket().display());
    for room in view.open_channels {
        println!(
            "vox daemon: holding room {} open",
            vox_core::node::link::b32_encode(&room.channel_id)
        );
    }
}

/// What a person is told when the foreground node will not attach: what to do, not which variant
/// lost.
fn refusal_words(r: &Refusal, account: &Account, node: &NodeName) -> String {
    match r {
        // A new person is sent here by `vox room list`'s "start one: vox daemon", and this is
        // the second thing they see: it says that `vox id` is what makes an identity.
        Refusal::NoIdentity { .. } | Refusal::NoSuchNode { .. } => format!(
            "this profile has no identity yet, so there is nothing to unlock.\n\
             \x20      Make one:  vox id\n\
             \x20      Then start the daemon again. Profile: {}",
            account.node_dir(node).display()
        ),
        Refusal::WrongPassphrase { .. } => "that identity passphrase is wrong.\n       The first \
             line piped to `vox daemon` is the identity passphrase; lines after it open rooms."
            .to_owned(),
        Refusal::Failed { why, .. } => why.clone(),
        other => other.to_string(),
    }
}

/// Detach every node and end the daemon, with the exit rules `vox daemon` has always had: a stop
/// that finished exits 0 saying which signal; one that gave up says so and fails (V210-93).
fn stop_daemon(
    rt: tokio::runtime::Runtime,
    router: &Router,
    presence: &vox_core::node::presence::NetPresence,
    signal: Option<crate::app::StopSignal>,
) -> Result<(), AppError> {
    let why = signal.map_or_else(|| "request".to_owned(), |s| s.name().to_owned());
    if signal.is_some() {
        say(format_args!("vox daemon: shutting down on {why}"));
    }
    let patience = shutdown_patience();
    let finished = rt.block_on(async {
        let finished =
            tokio::time::timeout(patience + Duration::from_millis(500), router.stop_all())
                .await
                .unwrap_or(false);
        // Every node is detached: the presence goes, and with it the port mapping (N-43).
        presence.close().await;
        finished
    });
    // The same bound on the runtime itself: dropping it waits for every blocking task, and a sync
    // session runs on one.
    rt.shutdown_timeout(SHUTDOWN_PATIENCE);
    if !finished {
        // **A stop that gave up is not a stop** (decider, V210-93). The daemon leaves, as it must,
        // but a node's ordered stop was cut short: the closes it had not yet sent never left, and
        // those peers learn it went only by their own timeouts.
        return Err(AppError::Refused {
            code: 1,
            message: format!(
                "the daemon did not finish stopping on {why} within {}s: its node was mid-way \
                 through a network exchange with a peer that is not answering. It left anyway, so \
                 a peer it had not yet said goodbye to learns it went only when its connection \
                 times out",
                patience.as_secs_f64()
            ),
        });
    }
    if signal.is_some() {
        say(format_args!("vox daemon: stopped by {why}"));
    } else {
        say(format_args!("vox daemon: stopped"));
    }
    Ok(())
}

/// Another daemon holds the account (D-1). Started by a client, there is nothing to do. Naming a
/// node, hand the node to the running daemon as a held session and stay until a stop signal.
fn already_running(
    args: &DaemonArgs,
    account: &Account,
    rt: tokio::runtime::Runtime,
    stop: &mut std::pin::Pin<Box<impl std::future::Future<Output = crate::app::StopSignal>>>,
    named: Option<NodeName>,
) -> Result<(), AppError> {
    let running = |why: &str| {
        format!(
            "a daemon is already running for {}{why}",
            account.data_root.display()
        )
    };
    if args.as_detached {
        eprintln!("vox daemon: {}", running(""));
        return Ok(());
    }
    let node = match named.or_else(|| {
        let mut d = account.nodes_on_disk();
        (d.len() == 1).then(|| d.pop()).flatten()
    }) {
        Some(n) => n,
        None => {
            return Err(AppError::Refused {
                code: 1,
                message: running("; name a node with --node to attach it there"),
            })
        }
    };
    let (identity, rooms) = match daemon_passphrases(&rt, stop, args.passphrase_file.clone())? {
        Asked::Got(got) => got,
        Asked::Stopped(signal) => {
            say(format_args!("vox daemon: stopped by {}", signal.name()));
            return Ok(());
        }
    };
    let socket = account.socket();
    let held = rt.block_on(async {
        if let Some(keep) = keep_source(args) {
            let mut d = DaemonClient::open(&socket)
                .await
                .map_err(|e| AppError::Usage(e.to_string()))?;
            match d
                .request(DaemonRequest::Attach {
                    node: node.clone(),
                    passphrase: Some(identity.clone()),
                    keep: Some(keep),
                    rooms: Vec::new(),
                    anchors: args.profile.anchors.clone(),
                })
                .await
                .map_err(|e| AppError::Usage(e.to_string()))?
            {
                DaemonFrame::Attached(_) => {}
                DaemonFrame::Refused(r) => {
                    return Err(AppError::Usage(refusal_words(&r, account, &node)))
                }
                other => return Err(AppError::Usage(format!("unexpected answer: {other:?}"))),
            }
        }
        let client = IpcClient::open_node(
            &socket,
            UseNode {
                node: node.clone(),
                attach: AttachMode::Hold,
                passphrase: Some(identity),
                anchors: args.profile.anchors.clone(),
            },
        )
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
        let mut client = client.map_err(|r| AppError::Usage(refusal_words(&r, account, &node)))?;
        for line in &rooms {
            open_rooms_over_socket(&mut client, line).await;
        }
        Ok::<_, AppError>(client)
    })?;
    let fp = held
        .me()
        .map(|f| vox_core::node::link::b32_encode(&f))
        .unwrap_or_default();
    println!("vox daemon: identity {fp}");
    println!("vox daemon: control socket {}", socket.display());
    println!("vox daemon: node {node} is held by the daemon already running here");
    let mut held = held;
    let ended = rt.block_on(async {
        tokio::select! {
            signal = stop => Ok(signal),
            gone = held.closed() => Err(gone),
        }
    });
    match ended {
        Ok(signal) => {
            // Closing the connection lets the node go: it detaches unless something else holds
            // it, or it was kept.
            drop(held);
            rt.shutdown_timeout(SHUTDOWN_PATIENCE);
            say(format_args!("vox daemon: stopped by {}", signal.name()));
            Ok(())
        }
        Err(()) => Err(AppError::Refused {
            code: 1,
            message: format!(
                "the daemon holding node {node} stopped, so this session ended with it"
            ),
        }),
    }
}

/// [`open_rooms_by_line`] over the socket: the whole line as a passphrase for every closed room,
/// then `<room> <passphrase>`.
async fn open_rooms_over_socket(client: &mut IpcClient, line: &str) {
    let Ok(Frame::Rooms { rooms }) = client.rooms().await else {
        return;
    };
    let mut opened = false;
    for (channel_id, _, open, _) in &rooms {
        if *open {
            continue;
        }
        if let Ok(Frame::Ok) = client
            .request(&Request::OpenRoom {
                channel_id: *channel_id,
                passphrase: line.to_owned(),
            })
            .await
        {
            opened = true;
        }
    }
    if opened {
        return;
    }
    if let Some((room, pass)) = line.split_once(' ') {
        let ids: Vec<_> = rooms.iter().map(|(id, _, _, _)| *id).collect();
        if let Ok(id) = crate::tunnel_cli::resolve_prefix(room, &ids) {
            let _ = client
                .request(&Request::OpenRoom {
                    channel_id: id,
                    passphrase: pass.to_owned(),
                })
                .await;
        }
    }
}
