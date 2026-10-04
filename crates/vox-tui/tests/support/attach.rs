//! Attaching a node before a one-shot verb, as a person does since ADR-026 L-2: `vox room`,
//! `vox trust`, `vox status`, `vox service`, `vox share`, `vox app`, `vox tunnel close` and
//! `vox doctor` refuse an unattached node ("attach it first: vox node attach X"). A proof that runs
//! one of them with no daemon holding its node first attaches it here — `vox node attach`, which
//! starts the data root's daemon if none runs — and, where its own staging starts a daemon of its
//! own afterwards (with its own `--listen` or `--anchor`), detaches it again so that daemon is the
//! one that runs.
//!
//! Included with `#[path]` by a proof, or by a support module, which is why not every item is used
//! by every includer.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long a detached node's auto-started daemon may take to exit (it lingers 1 s, ADR-026 L-8).
const GONE_WITHIN: Duration = Duration::from_secs(20);

/// A data root, its config directory and the identity passphrase of its node.
#[derive(Clone, Debug)]
pub struct Root {
    pub data: PathBuf,
    pub cfg: PathBuf,
    pub passphrase: String,
}

impl Root {
    /// The data root `data` with its config directory at `data/cfg`, as the harness lays one out.
    pub fn at(data: &Path, passphrase: &str) -> Self {
        Self {
            data: data.to_path_buf(),
            cfg: data.join("cfg"),
            passphrase: passphrase.to_owned(),
        }
    }

    fn vox(&self, args: &[&str], stdin: &str) -> (bool, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vox"))
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_NODE")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {args:?}: {e}"));
        let _ = child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(stdin.as_bytes());
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: wait for vox {args:?}: {e}"));
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// `vox node attach <node> --passphrase-file -`: the node runs in the data root's daemon
    /// (started if none runs). `PRODUCT (staging):` if it fails.
    pub fn attach(&self, node: &str) {
        let (ok, said) = self.vox(
            &["node", "attach", node, "--passphrase-file", "-"],
            &format!("{}\n", self.passphrase),
        );
        assert!(
            ok,
            "PRODUCT (staging): `vox node attach {node}` in {} failed: {said}",
            self.data.display()
        );
    }

    /// `vox node detach <node>`, then wait until no daemon holds the data root's lock: a daemon a
    /// client started exits once it has no node and no client (ADR-026 L-8), so a daemon the proof
    /// starts next is the one that runs. `PRODUCT (staging):` if the detach fails or the daemon
    /// stays.
    pub fn detach(&self, node: &str) {
        let (ok, said) = self.vox(&["node", "detach", node], "");
        assert!(
            ok,
            "PRODUCT (staging): `vox node detach {node}` in {} failed: {said}",
            self.data.display()
        );
        let t0 = Instant::now();
        while self.daemon_running() {
            assert!(
                t0.elapsed() < GONE_WITHIN,
                "PRODUCT (staging): the daemon {} started for `vox node attach` did not exit \
                 within {GONE_WITHIN:?} of its only node's detach",
                self.data.display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run `f` with `node` attached, then detach it and wait for the daemon that attach started to
    /// go: for a proof's one-shot setup verbs before it starts a daemon of its own.
    pub fn attached<T>(&self, node: &str, f: impl FnOnce() -> T) -> T {
        self.attach(node);
        let out = f();
        self.detach(node);
        out
    }

    /// Run `f`, a one-shot verb, with `node` attached: as it is when a daemon already holds this
    /// data root (the proof's own `vox daemon`), else attached for it and let go after.
    pub fn ensure<T>(&self, node: &str, f: impl FnOnce() -> T) -> T {
        if self.daemon_running() {
            f()
        } else {
            self.attached(node, f)
        }
    }

    /// Whether a process holds the data root's daemon lock.
    pub fn daemon_running(&self) -> bool {
        let Ok(file) = std::fs::File::open(self.data.join(".daemon").join("lock")) else {
            return false;
        };
        match file.try_lock() {
            Ok(()) => {
                let _ = file.unlock();
                false
            }
            Err(std::fs::TryLockError::WouldBlock) => true,
            Err(std::fs::TryLockError::Error(_)) => false,
        }
    }
}

/// The data root's account socket (`<data>/.daemon/vox.sock`, or the short fallback a long path
/// takes), as the shipped client computes it: every client reaches a node through it since the
/// per-node socket went (ADR-026 C-1, C-2).
pub fn account_socket(data: &Path) -> PathBuf {
    vox_core::node::paths::Account::of(Some(data), Some(&data.join("cfg")))
        .unwrap_or_else(|e| panic!("APPARATUS: the account of {}: {e}", data.display()))
        .socket()
}

/// A control-socket client acting as node `node` of the data root `data`, through the daemon's
/// account socket, never attaching it (a one-shot verb's `Use`): what `vox room …` sends its
/// requests on. `Err` says why the daemon could not be reached or refused the node.
pub async fn node_client(
    data: &Path,
    node: &str,
) -> Result<vox_core::node::ipc::IpcClient, String> {
    client_at(&account_socket(data), node).await
}

/// [`node_client`] on the account socket at `socket` (as a daemon names it in "vox daemon:
/// control socket …").
pub async fn client_at(
    socket: &Path,
    node: &str,
) -> Result<vox_core::node::ipc::IpcClient, String> {
    use vox_core::node::daemonipc::{AttachMode, UseNode};
    let name = vox_core::node::paths::NodeName::parse(node)
        .map_err(|e| format!("APPARATUS: node name {node:?}: {e}"))?;
    let using = UseNode {
        node: name,
        attach: AttachMode::No,
        passphrase: None,
        anchors: Vec::new(),
    };
    match vox_core::node::ipc::IpcClient::open_node(socket, using).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(refused)) => Err(format!("the daemon refused node {node}: {refused:?}")),
        Err(e) => Err(format!("the daemon's socket did not answer: {e}")),
    }
}

/// [`node_client`] for the node `paths` resolves: its data root's account socket, as that node.
pub async fn paths_client(
    paths: &vox_core::node::paths::Paths,
) -> Result<vox_core::node::ipc::IpcClient, String> {
    use vox_core::node::daemonipc::{AttachMode, UseNode};
    let name = paths
        .profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("APPARATUS: no node name in {}", paths.profile_dir.display()))?;
    let using = UseNode {
        node: vox_core::node::paths::NodeName::parse(name)
            .map_err(|e| format!("APPARATUS: node name {name:?}: {e}"))?,
        attach: AttachMode::No,
        passphrase: None,
        anchors: Vec::new(),
    };
    match vox_core::node::ipc::IpcClient::open_node(&paths.account().socket(), using).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(refused)) => Err(format!("the daemon refused node {name}: {refused:?}")),
        Err(e) => Err(format!("the daemon's socket did not answer: {e}")),
    }
}

/// The verbs that refuse a node no daemon holds (ADR-026 L-2, ruled).
pub const NEEDS_ATTACHED: &[&str] = &[
    "room", "trust", "status", "service", "share", "app", "tunnel", "doctor",
];

/// The node to attach before running `argv` in data root `data` the way a person must since
/// ADR-026 L-2 — its `--node`, else `default` — or `None`: the verb needs no attached node, a daemon
/// already holds the root, or there is no such node (the verb then says so itself).
pub fn needs(data: &Path, argv: &[&str]) -> Option<String> {
    if !argv.first().is_some_and(|v| NEEDS_ATTACHED.contains(v)) {
        return None;
    }
    let root = Root::at(data, "");
    if root.daemon_running() {
        return None;
    }
    let node = argv
        .windows(2)
        .find(|w| w[0] == "--node")
        .map_or("default", |w| w[1])
        .to_owned();
    data.join("nodes").join(&node).exists().then_some(node)
}
