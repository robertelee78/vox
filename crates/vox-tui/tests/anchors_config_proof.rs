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
//! The host's invite names the anchor by the very fingerprint `vox node` wrote to the file, and
//! nothing else could have told the host about that anchor (there is no `--anchor` anywhere), so
//! what the proof shows is the file being read. There is no "no anchors file" control: an anchor
//! only bridges hosts that cannot otherwise find each other, so a host with no anchors file must
//! still serve, and refusing for want of one is a defect (#302), not a control.

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
    at.to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned()
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
        let out = child.stdout.take().expect("APPARATUS: vox's piped stdout");
        let (tx, rx) = mpsc::channel();
        let out_tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if out_tx.send(line).is_err() {
                    break;
                }
            }
        });
        // stderr goes to the same lines, marked, because what a node says there (which anchor it
        // reached) is part of what a person sees.
        if let Some(err) = child.stderr.take() {
            let n = name.to_owned();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    eprintln!("[{n} stderr] {line}");
                    if tx.send(format!("[stderr] {line}")).is_err() {
                        break;
                    }
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
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&shared_cfg, &anchor_dir, &host_dir, &guest_dir] {
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
    let spec = body
        .lines()
        .find(|l| !l.trim_start().starts_with('#') && l.contains('@') && !l.contains("0.0.0.0"))
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: the anchors file must hold a dialable spec, not a wildcard bind:\n{body}"
            )
        });
    let file_fp = spec
        .split_once('@')
        .map(|(fp, _)| fp.trim().to_owned())
        .unwrap_or_default();

    // Listening on loopback only, it says its spec is for this machine, in the words a person
    // uses: a node, never a "profile" (#428).
    let here = anchor.expect_line("the anchor's this-machine-only spec", |l| {
        l.starts_with("vox node: on this machine only")
    });
    assert!(
        here == "vox node: on this machine only, for a node that reads another anchors file:"
            && !anchor.seen.join("\n").to_lowercase().contains("profile"),
        "PRODUCT: `vox node` must say its loopback spec is \"on this machine only, for a node that \
         reads another anchors file:\" and never say \"profile\"; it said {here:?}:\n{}",
        anchor.seen.join("\n")
    );

    // A host in its own profile, on the same machine, with **no `--anchor`**.
    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &shared_cfg,
        &[
            "serve".into(),
            "1=1".into(),
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
        address.contains(&format!("?a={file_fp}&b=")),
        "PRODUCT: the invite must carry the anchor the host learned from the file ({file_fp}), so \
         a guest elsewhere can reach it: {address}"
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

    drop(host);
    drop(anchor);
}

/// **An anchor may be named by hostname** (ADR-017 decision 7, RP-06). A person configuring an
/// anchor has a machine in mind, and that machine has a name; a home connection's address
/// changes whenever the ISP decides, so a spec that only takes an address silently points
/// nowhere after the next change.
///
/// The host here is told the anchor as `<fp>@localhost:<port>`, the way a person types it into
/// the anchors file. Two things must follow, both as a person sees them:
///
/// - the host says it **connected to that anchor** (a name resolved to the wrong place says
///   "dialling this anchor failed" instead);
/// - a guest whose **only** way to the host is that anchor joins. The invite names the host's
///   own address as well, and on one machine a guest would simply dial it, which is right
///   (ADR-012: an anchor only bridges hosts that cannot otherwise find each other) and proves
///   nothing about the anchor. So the guest is handed the invite with the host's own address
///   replaced by one nobody answers, which is what a host behind NAT looks like from outside.
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
    let (fp, addr) = printed.split_once('@').unwrap_or_else(|| {
        panic!("PRODUCT (staging): `vox node` printed a spec with no @: {printed}")
    });
    let port = addr.rsplit('/').next().unwrap_or_else(|| {
        panic!("PRODUCT (staging): `vox node` printed a spec with no port: {printed}")
    });
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
            "1=1".into(),
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
        address.contains(&format!("a={fp}")),
        "PRODUCT: the invite must carry the anchor the host found by the name {by_name}, so a \
         guest can reach it: {address}"
    );
    // The fingerprint as a node's messages abbreviate it.
    let short = &fp[..26];
    let reached = format!("connection to {short} — connected to this anchor");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !host.seen.iter().any(|l| l.contains(&reached)) {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "PRODUCT: within 60 s the host never said it connected to the anchor it was told as \
             {by_name}. It said:\n{}",
            host.seen.join("\n")
        );
        match host.lines.recv_timeout(left) {
            Ok(l) => {
                eprintln!("[host] {l}");
                host.seen.push(l);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                "PRODUCT: the host exited before connecting to the anchor named {by_name}. It \
                 said:\n{}",
                host.seen.join("\n")
            ),
        }
    }
    eprintln!("[proof] the host connected to the anchor named {by_name}");

    // The guest's invite, with the host's own address (the entry its `r=` pins) made one that
    // nobody answers: the anchor is now the only way in.
    let (base, query) = address
        .split_once('?')
        .unwrap_or_else(|| panic!("PRODUCT: the invite has no query: {address}"));
    let host_id = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("r="))
        .unwrap_or_else(|| panic!("PRODUCT (staging): the invite pins no host (r=): {address}"));
    let (mut current, mut replaced, mut kept) = (None, false, Vec::new());
    for kv in query.split('&') {
        if let Some(id) = kv.strip_prefix("a=") {
            current = Some(id);
        } else if kv.starts_with("b=") && current == Some(host_id) {
            if !replaced {
                kept.push("b=/ip4/127.0.0.1/udp/1");
                replaced = true;
            }
            continue;
        }
        kept.push(kv);
    }
    assert!(
        replaced,
        "PRODUCT (staging): the invite names no address of the host itself to \
         make unreachable: {address}"
    );
    let behind_nat = format!("{base}?{}", kept.join("&"));
    eprintln!("[proof] the guest is given {behind_nat}");

    let (ok, out, err) = vox_once(
        &guest_dir,
        &guest_cfg,
        &[
            "connect".into(),
            behind_nat.clone(),
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
