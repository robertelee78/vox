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
