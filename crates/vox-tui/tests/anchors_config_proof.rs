//! **Anchors are configuration, not an argument** (ADR-017 decision 7, M17.4), proved by
//! running the real binaries.
//!
//! The complaint this closes, in ADR-017's words: `--anchor <fp>@<addr>` on every command
//! was "the second-worst step" in the flow — a 52-character fingerprint and a multiaddr
//! pasted into every invocation. Decision 7 said `vox node` should write its own spec so a
//! client on the same machine needs no flag. That was recorded as shipped and **was not
//! built**; the ADR now says so, and this is the proof that it is.
//!
//! What runs here: real `vox` child processes, no library calls. `vox node` starts, and a
//! **separate** `vox` process in the same profile reaches a room through that anchor with
//! no `--anchor` anywhere on its command line.
//!
//! The negative control is the point of the second half: the same `vox serve` in a profile whose
//! config directory holds **no** anchors file refuses to mint an address (this machine has no
//! address a guest could reach and no anchor to relay through), so what the first half proves
//! is the file being read, not the host finding an anchor some other way.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Write the room passphrase `pass` beside the profile at `dir`, for `--passphrase-file`: a
/// room passphrase is never taken from argv or the environment (V210-72).
fn room_pass_file(dir: &std::path::Path, pass: &str) -> String {
    std::fs::create_dir_all(dir).expect("APPARATUS: create the profile dir");
    let at = dir.join("room-passphrase");
    std::fs::write(&at, pass).expect("APPARATUS: write the room passphrase file");
    at.to_str().unwrap().to_owned()
}
const VOX: &str = env!("CARGO_BIN_EXE_vox");
const LINE_TIMEOUT: Duration = Duration::from_secs(180);

struct Proc {
    name: &'static str,
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Proc {
    fn spawn(
        name: &'static str,
        data: &std::path::Path,
        cfg: &std::path::Path,
        args: &[String],
    ) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", cfg)
            .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name}: {e}"));
        let out = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        if let Some(err) = child.stderr.take() {
            let n = name.to_owned();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    eprintln!("[{n} stderr] {line}");
                }
            });
        }
        Self {
            name,
            child,
            lines: rx,
            seen: Vec::new(),
        }
    }

    fn expect_line(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + LINE_TIMEOUT;
        for l in &self.seen {
            if pred(l) {
                return l.clone();
            }
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "PRODUCT: {} never said {what} within {LINE_TIMEOUT:?}. It said:\n{}",
                self.name,
                self.seen.join("\n")
            );
            match self.lines.recv_timeout(left.min(Duration::from_secs(5))) {
                Ok(l) => {
                    eprintln!("[{}] {l}", self.name);
                    let hit = pred(&l);
                    self.seen.push(l.clone());
                    if hit {
                        return l;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "PRODUCT: {} exited before saying {what}. It said:\n{}",
                    self.name,
                    self.seen.join("\n")
                ),
            }
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn vox_once(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[String],
) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: run vox: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| panic!("PRODUCT: {line:?} does not start with {label:?}"))
        .trim()
        .to_owned()
}

#[test]
#[ignore = "production Argon2id + real binaries; CI runs it in release"]
fn a_client_on_the_anchors_machine_needs_no_anchor_flag() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    // **The config directory is machine-wide; only the data directory is per profile**
    // (`Paths::resolve` — `profile_dir` is under the data root, `config_dir` is not). That is
    // what makes decision 7 work: `vox node` writes one anchors file and every profile on the
    // machine reads it. So these processes share `shared_cfg` and have their own data roots,
    // which is exactly how three `vox` processes on one machine really sit.
    let shared_cfg = tmp.path().join("config");
    let other_cfg = tmp.path().join("config-elsewhere");
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    let control_dir = tmp.path().join("control");
    for d in [
        &shared_cfg,
        &other_cfg,
        &anchor_dir,
        &host_dir,
        &guest_dir,
        &control_dir,
    ] {
        std::fs::create_dir_all(d).expect("APPARATUS: create a profile dir");
    }

    // `vox node` — and it must WRITE the file, not merely print a spec to paste.
    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &shared_cfg,
        &["node".into(), "--listen".into(), "127.0.0.1:0".into()],
    );
    let wrote = anchor.expect_line("the anchors file to be written", |l| l.contains("wrote "));
    let anchors_path = wrote
        .split("wrote ")
        .nth(1)
        .unwrap_or_else(|| panic!("PRODUCT: `vox node` said it wrote no path: {wrote:?}"))
        .trim()
        .to_owned();
    let body = std::fs::read_to_string(&anchors_path).unwrap_or_else(|e| {
        panic!("PRODUCT: `vox node` said {wrote:?}, but the file cannot be read: {e}")
    });
    assert!(
        body.lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains('@') && !l.contains("0.0.0.0")),
        "PRODUCT: the anchors file must hold a dialable spec, not a wildcard bind:\n{body}"
    );

    // A host in its own profile, on the same machine, with **no `--anchor`**.
    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &shared_cfg,
        &[
            "serve".into(),
            "1".into(),
            "--at".into(),
            "127.0.0.1:1".into(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    let address = after_label(
        &host.expect_line("the vox:// address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("the passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    assert!(
        address.contains("?a=") && address.contains("&b="),
        "PRODUCT: the invite must carry the anchor the host learned from the file, so a guest \
         elsewhere can reach it: {address}"
    );

    // The proof: a guest in its own profile, sharing only the machine-wide config, joins
    // with **no `--anchor` argument anywhere**.
    let (ok, out, err) = vox_once(
        &guest_dir,
        &shared_cfg,
        &[
            "connect".into(),
            address.clone(),
            "--passphrase-file".into(),
            room_pass_file(&guest_dir, &passphrase),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    assert!(
        ok,
        "PRODUCT: a client on the anchor's machine must join with NO --anchor flag.\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("joined"),
        "PRODUCT: connect should say it joined:\n{out}"
    );

    // The negative control: the same `vox serve`, in a profile whose config directory holds no
    // anchors file, has no anchor to relay through and refuses. A host that served here would
    // mean the first half's anchor did not come from the file.
    let mut control = Command::new(VOX)
        .args([
            "serve",
            "1",
            "--at",
            "127.0.0.1:1",
            "--listen",
            "127.0.0.1:0",
        ])
        .env("VOX_DATA_DIR", &control_dir)
        .env("VOX_CONFIG_DIR", &other_cfg)
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn the control host: {e}"));
    let deadline = Instant::now() + Duration::from_secs(90);
    while control
        .try_wait()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for the control host: {e}"))
        .is_none()
    {
        if Instant::now() >= deadline {
            let _ = control.kill();
            let out = control
                .wait_with_output()
                .unwrap_or_else(|e| panic!("APPARATUS: reap the control host: {e}"));
            panic!(
                "PRODUCT: `vox serve` with no anchors file was still serving after 90 s, so the \
                 first half's anchor need not have come from the file.\nstdout:\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = control
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: reap the control host: {e}"));
    let (cout, cerr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    eprintln!("[proof] the control host with no anchors file: {cerr}");
    assert!(
        !out.status.success() && cerr.contains("no anchor to relay through"),
        "PRODUCT: `vox serve` with no anchors file did not refuse for want of an anchor \
         ({}).\nstdout:\n{cout}\nstderr:\n{cerr}",
        out.status
    );

    drop(host);
    drop(anchor);
}
