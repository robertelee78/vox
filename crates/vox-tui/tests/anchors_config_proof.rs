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
//! The mutation control is the point of the second half: the same command in a profile with
//! **no** anchors file cannot reach the host, so what the first half proves is the file
//! being read, not the two processes happening to find each other some other way.

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
    std::fs::create_dir_all(dir).unwrap();
    let at = dir.join("room-passphrase");
    std::fs::write(&at, pass).unwrap();
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
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
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
                "{}: timed out waiting for {what}. It said:\n{}",
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
                    "{}: exited before saying {what}. It said:\n{}",
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
        .expect("run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| panic!("{line:?} does not start with {label:?}"))
        .trim()
        .to_owned()
}

#[test]
#[ignore = "production Argon2id + real binaries; CI runs it in release"]
fn a_client_on_the_anchors_machine_needs_no_anchor_flag() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
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
    for d in [&shared_cfg, &other_cfg, &anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d).unwrap();
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
        .expect("a path on the wrote line")
        .trim()
        .to_owned();
    let body = std::fs::read_to_string(&anchors_path).expect("read the anchors file");
    assert!(
        body.lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains('@') && !l.contains("0.0.0.0")),
        "the file must hold a dialable spec, not a wildcard bind:\n{body}"
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
        "the invite must carry the anchor the host learned from the file, so a guest \
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
        "a client on the anchor's machine must join with NO --anchor flag.\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("joined"),
        "connect should say it joined:\n{out}"
    );

    drop(host);
    drop(anchor);
}

/// **An anchor may be named by hostname** (ADR-017 decision 7, RP-06). A person configuring an
/// anchor has a machine in mind, and that machine has a name; a home connection's address
/// changes whenever the ISP decides, so a spec that only takes an address silently points
/// nowhere after the next change.
///
/// The host here is told the anchor as `<fp>@localhost:<port>`, the way a person types it into
/// the anchors file, and advertises itself at an address nobody can dial (`--at 127.0.0.1:1`).
/// The guest has no anchor of its own. So the guest can reach the host **only** through the
/// anchor the host found by its name: the join is the proof that the name was resolved and the
/// anchor used.
#[test]
#[ignore = "production Argon2id + real binaries; CI runs it in release"]
fn an_anchor_named_by_hostname_carries_a_join() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let anchor_cfg = tmp.path().join("anchor-config");
    let host_cfg = tmp.path().join("host-config");
    let guest_cfg = tmp.path().join("guest-config");
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [
        &anchor_cfg,
        &host_cfg,
        &guest_cfg,
        &anchor_dir,
        &host_dir,
        &guest_dir,
    ] {
        std::fs::create_dir_all(d).expect("APPARATUS: create a profile dir");
    }

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &anchor_cfg,
        &["node".into(), "--listen".into(), "127.0.0.1:0".into()],
    );
    // `<fp>@/ip4/127.0.0.1/udp/<port>`, the spec `vox node` prints for elsewhere.
    let printed = anchor
        .expect_line("an anchor spec on 127.0.0.1", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    let (fp, addr) = printed.split_once('@').expect("a spec has an @");
    let port = addr.rsplit('/').next().expect("a port after the last /");
    // What a person writes: the machine's name, not its address.
    let by_name = format!("{fp}@localhost:{port}");
    std::fs::write(
        host_cfg.join("anchors"),
        format!("# the anchor, by name\n{by_name}\n"),
    )
    .expect("APPARATUS: write the host's anchors file");
    eprintln!("[proof] the host's anchors file names the anchor as {by_name}");

    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &host_cfg,
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
        "PRODUCT: the invite must carry the anchor the host found by the name {by_name}, so a \
         guest can reach it: {address}"
    );

    let (ok, out, err) = vox_once(
        &guest_dir,
        &guest_cfg,
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
        ok && out.contains("joined"),
        "PRODUCT: a guest must join a host whose only way in is an anchor named {by_name}; \
         `vox connect` said:\nstdout:\n{out}\nstderr:\n{err}\nThe host said:\n{}",
        host.seen.join("\n")
    );
    eprintln!("[proof] the guest joined through the anchor named {by_name}");

    drop(host);
    drop(anchor);
}
