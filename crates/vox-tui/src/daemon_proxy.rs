//! The daemon's `.vox` proxy (ADR-028 S-5, amending ADR-017 5.1–5.2).
//!
//! One SOCKS5 proxy per daemon, on `127.0.0.1:1080` unless `--proxy` or `VOX_PROXY` says
//! otherwise. It runs while any node is attached: it binds when the first one attaches and stops
//! when the last one detaches. It carries every attached node's rooms. A name is resolved against
//! each attached node, and the tunnel is dialled through the node that holds the room the name
//! led to.
//!
//! `vox up` starts nothing. It asks the daemon where the proxy is, through [`ProxyReport`], and
//! prints that with the `ssh` block. A proxy that could not bind (the port is taken, or the
//! address is not loopback) keeps its reason, which `vox up` then says. A bind failure never
//! fails an attach: the node is still useful without the proxy.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::net::UnixStream;
use tokio::runtime::Handle;
use vox_core::hash::Digest32;
use vox_core::node::actor::NodeHandle;
use vox_core::node::nameipc::NameRequest;
use vox_core::node::resolver::ServiceRoom;
use vox_core::transport::quic::VoxConnection;

/// Where the proxy listens unless configured otherwise: the registered SOCKS port, on loopback.
pub const DEFAULT_PROXY: &str = "127.0.0.1:1080";

/// The proxy's address for a daemon started without `vox daemon`'s flags (`vox node`):
/// `VOX_PROXY`, else [`DEFAULT_PROXY`].
///
/// # Errors
/// `VOX_PROXY` is set but is not an address.
pub fn configured() -> Result<SocketAddr, crate::app::AppError> {
    let text = std::env::var("VOX_PROXY").unwrap_or_else(|_| DEFAULT_PROXY.to_owned());
    text.trim().parse().map_err(|_| {
        crate::app::AppError::Usage(format!(
            "VOX_PROXY is {text:?}, which is not an address such as {DEFAULT_PROXY}"
        ))
    })
}

/// The daemon's one proxy and what became of it.
pub struct DaemonProxy {
    bind: SocketAddr,
    state: Mutex<State>,
}

enum State {
    /// No node attached, so no proxy.
    Off,
    /// Listening at `bound` until `task` is aborted.
    Up {
        bound: SocketAddr,
        task: tokio::task::AbortHandle,
    },
    /// It could not bind, for this reason.
    Failed(String),
}

impl DaemonProxy {
    /// A proxy that is to listen at `bind`, not yet bound.
    #[must_use]
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            state: Mutex::new(State::Off),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bind and serve, if it is not serving: across the nodes `nodes` lists when each connection
    /// asks. A bind that fails is kept as the reason and said in the daemon's log; it is tried
    /// again at the next attach.
    pub fn up(&self, rt: &Handle, nodes: Nodes) {
        let mut state = self.state();
        if matches!(*state, State::Up { .. }) {
            return;
        }
        *state = match bind(self.bind, rt) {
            Ok(listener) => {
                let bound = listener.local_addr().unwrap_or(self.bind);
                let listed = Arc::clone(&nodes.0);
                let cut_list = Arc::clone(&nodes.0);
                let nodes = Arc::new(nodes);
                let task = rt.spawn(vox_core::node::up::serve_reporting(
                    listener,
                    Arc::clone(&nodes),
                    nodes,
                    Arc::new(vox_core::tunnel::udp::UdpFlows::default()),
                    // Each note is the event of the node that holds the room, which the TUI, the
                    // app, `vox up --watch` and the decision record take as they take any.
                    move |room: &Digest32, port: u16| {
                        if let Some((_, node)) = holder(&cut_list(), room) {
                            node.proxy_reach_withdrawn(*room, port);
                        }
                    },
                    move |room: Option<Digest32>, note: vox_core::node::tunnel::TunnelNote| {
                        let nodes = listed();
                        match room.and_then(|room| holder(&nodes, &room)) {
                            Some((_, node)) => node.proxy_note(note),
                            // A name that led nowhere is said to every attached node.
                            None => {
                                for (_, node) in &nodes {
                                    node.proxy_note(note.clone());
                                }
                            }
                        }
                    },
                ));
                eprintln!("vox daemon: the .vox proxy is on {bound}");
                State::Up {
                    bound,
                    task: task.abort_handle(),
                }
            }
            Err(why) => {
                eprintln!("vox daemon: {why}");
                State::Failed(why)
            }
        };
    }

    /// Stop serving: the last node detached.
    pub fn down(&self) {
        let mut state = self.state();
        if let State::Up { bound, task } = &*state {
            task.abort();
            eprintln!("vox daemon: the .vox proxy on {bound} stopped: no node is attached");
        }
        *state = State::Off;
    }

    /// Where it listens, or why it does not.
    ///
    /// # Errors
    /// The bind's reason, or that no node is attached.
    pub fn report(&self) -> Result<SocketAddr, String> {
        match &*self.state() {
            State::Up { bound, .. } => Ok(*bound),
            State::Failed(why) => Err(why.clone()),
            State::Off => Err("no node is attached, so the .vox proxy is not running".to_owned()),
        }
    }
}

fn bind(addr: SocketAddr, rt: &Handle) -> Result<tokio::net::TcpListener, String> {
    if !addr.ip().is_loopback() {
        return Err(format!(
            "the .vox proxy was not started: {addr} is not on loopback, and the proxy carries \
             this machine's rooms to whoever reaches it. Set --proxy or VOX_PROXY to an address \
             on 127.0.0.1 or ::1"
        ));
    }
    let std = std::net::TcpListener::bind(addr)
        .and_then(|l| l.set_nonblocking(true).map(|()| l))
        .map_err(|e| {
            format!(
                "the .vox proxy could not listen on {addr}: {e}. Free the port, or set --proxy \
                 or VOX_PROXY to another"
            )
        })?;
    let _in_runtime = rt.enter();
    tokio::net::TcpListener::from_std(std)
        .map_err(|e| format!("the .vox proxy could not listen on {addr}: {e}"))
}

/// The attached nodes, as the proxy asks for them: per connection, so a node attached after
/// the proxy came up is carried at once.
pub struct Nodes(pub Arc<dyn Fn() -> Vec<(String, NodeHandle)> + Send + Sync>);

impl vox_core::node::up::Names for Nodes {
    async fn lookup(&self, name: &str) -> Result<ServiceRoom, String> {
        let mut first = None;
        for (_, node) in (self.0)() {
            match node.resolve_name(name).await {
                Ok(room) => return Ok(room),
                Err(why) => {
                    first.get_or_insert(why);
                }
            }
        }
        Err(first.unwrap_or_else(|| "no node is attached".to_owned()))
    }
}

impl vox_core::node::up::HostDialer for Nodes {
    async fn connection(
        &self,
        host: &Digest32,
        channel_id: &Digest32,
    ) -> vox_core::error::Result<Arc<VoxConnection>> {
        let Some((_, node)) = holder(&(self.0)(), channel_id).cloned() else {
            return Err(vox_core::error::Error::Unreachable(
                "no attached node holds that room open any more",
            ));
        };
        node.member_dialer()
            .await?
            .connection(host, channel_id)
            .await
    }
}

/// The attached node that holds `room` open.
fn holder<'a>(
    nodes: &'a [(String, NodeHandle)],
    room: &Digest32,
) -> Option<&'a (String, NodeHandle)> {
    nodes.iter().find(|(_, node)| {
        node.view()
            .channels
            .iter()
            .any(|c| c.channel_id == *room && c.open)
    })
}

/// `vox up`'s question to the daemon: where is the proxy? Answered with its address or the
/// reason it is not running, then the connection ends. Served by the daemon, not the node,
/// because the proxy is the daemon's (ADR-026 S-5's extension).
#[derive(Clone)]
pub struct ProxyReport {
    /// The daemon's proxy.
    pub proxy: Arc<DaemonProxy>,
    /// What brings it up, should a node be attached while it is not running.
    pub up: Arc<dyn Fn() + Send + Sync>,
}

impl ProxyReport {
    /// Whether `body` is `vox up`'s question.
    #[must_use]
    pub fn claims(body: &[u8]) -> bool {
        matches!(NameRequest::parse(body), Some(NameRequest::Up(_)))
    }

    /// Answer on `stream`.
    pub async fn serve(&self, mut stream: UnixStream) {
        // `vox up` attached its node before it asked, so the proxy should be up; a bind that
        // failed earlier is tried once more, as an attach would.
        if self.proxy.report().is_err() {
            (self.up)();
        }
        let body = match self.proxy.report() {
            Ok(bound) => vox_core::node::nameipc::up_bound(bound),
            Err(reason) => vox_core::node::ipc::Frame::Error { reason }.to_bytes(),
        };
        let _ = vox_core::node::ipc::write_frame(&mut stream, &body).await;
    }
}
