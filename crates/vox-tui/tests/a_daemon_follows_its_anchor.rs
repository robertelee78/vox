//! A running daemon must follow its anchor when the anchor moves.
//!
//! An anchor spec may name a host rather than an address (M17.5), and the stated reason
//! it may is that a home connection's address changes whenever the ISP decides — so a
//! person should not have to re-issue it to every client. The implementation resolved
//! once, when the process read its configuration, so a daemon that runs for days held
//! whatever the name meant at startup and redialled that address for ever.
//!
//! The failure attributes badly, which is what makes it worth a gate: the anchor is up,
//! the name is right, and the client says only that it cannot reach a peer. Nothing in
//! that points at a stale address.
//!
//! **What this drives, with real binaries.** A daemon starts with an anchors file naming
//! an anchor that is not there. While it runs, the file is rewritten to name the real
//! one — the same edit a dynamic-DNS update amounts to from the node's point of view,
//! since both change what the configuration resolves to. The daemon must pick it up
//! without being restarted, and the proof of that is a room joined *through* the anchor
//! afterwards, not a log line saying it noticed.
//!
//! **What it does not prove.** A name whose A record moves while the file is untouched
//! is the same code path — the refresh re-reads and re-parses, and parsing is what
//! resolves — but this machine has no DNS record it can move, so that step is reasoned
//! rather than measured. Closing it needs a resolver the proof owns. Recorded here
//! rather than implied by a passing test.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};

use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";

/// Longer than the daemon's own 30s refresh, with room for a dial afterwards.
const FOLLOW_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(data: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    vox_stdin(data, cfg, args, None)
}

/// `vox`, optionally with something piped to its stdin (`room create` wants a passphrase).
fn vox_stdin(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    input: Option<&str>,
) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env_remove("VOX_ROOM")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("vox stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
        drop(pipe);
    }
    let out = child.wait_with_output().expect("vox ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id, a real anchor and a 30s refresh; CI runs it in release"]
fn a_daemon_picks_up_an_anchor_that_moved_under_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();

    // ---- a real anchor, on a port nobody knew at startup ----
    let anchor_data = tmp.path().join("anchor-data");
    let anchor_cfg = tmp.path().join("anchor-cfg");
    std::fs::create_dir_all(&anchor_cfg).unwrap();
    let mut anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_data)
            .env("VOX_CONFIG_DIR", &anchor_cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox node"),
    );
    // `vox node` writes its own spec into its config dir; that file is the truth.
    let anchors_file = anchor_cfg.join("anchors");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let real_spec = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the anchor never wrote its spec to {}",
            anchors_file.display()
        );
        if let Ok(text) = std::fs::read_to_string(&anchors_file) {
            if let Some(line) = text
                .lines()
                .map(str::trim)
                .find(|l| l.contains("127.0.0.1") && l.contains('@'))
            {
                break line.to_owned();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let _ = anchor.0.stdout.take();

    // ---- a client profile, and an anchors file pointing at nothing ----
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
    {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let node = rt
            .block_on(async {
                vox_core::node::actor::Node::spawn_with(
                    paths.clone(),
                    std::sync::Arc::new(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs())
                    }),
                    vox_core::atrest::sek::Argon2Profile::default(),
                )
            })
            .unwrap();
        rt.block_on(async {
            assert!(node
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret(IDENTITY),
                })
                .await
                .is_done());
            let _ = node.apply(NodeCommand::Shutdown).await;
        });
        drop(rt);
    }
    // The same identity, a different port: reachable by nobody. This stands in for the
    // address a name used to resolve to.
    let wrong_spec = {
        let (id, _) = real_spec.split_once('@').expect("a well-formed spec");
        format!("{id}@/ip4/127.0.0.1/udp/9")
    };
    std::fs::write(anchors_file_for(&cfg), format!("{wrong_spec}\n")).unwrap();

    // ---- the daemon starts against the address that is wrong ----
    let mut daemon = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(tmp.path().join("daemon.err")).unwrap(),
        ))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = daemon.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let _daemon = Proc(daemon);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if vox(&data, &cfg, &["room", "list"]).0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // ---- the anchor moves: the configuration is rewritten under the running daemon ----
    std::fs::write(anchors_file_for(&cfg), format!("{real_spec}\n")).unwrap();

    // ---- it must reach the anchor without being restarted ----
    // Creating a room and getting an invite that names the anchor is the observable
    // consequence: a link carries the anchors the node has actually reached, so an
    // invite naming this one is the node saying it followed.
    let (ok, _, err) = vox_stdin(
        &data,
        &cfg,
        &["room", "create", "--name", "mission"],
        Some("a room passphrase\n"),
    );
    assert!(ok, "room create on the daemon: {err}");
    let room = {
        let (_, out, _) = vox(&data, &cfg, &["room", "list"]);
        out.split_whitespace()
            .find(|w| w.len() == 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
            .expect("a room id")
            .to_owned()
    };

    // **The address, not the identity.** The wrong spec names the same identity on a
    // dead port — that is what makes it a stand-in for an anchor that moved — so looking
    // for the fingerprint in the invite proves nothing: it is there either way. A first
    // version of this gate did exactly that and passed in 1.8 seconds, which is less
    // than the refresh interval and therefore could not have been a follow at all.
    let real_port = real_spec
        .rsplit('/')
        .next()
        .expect("a port in the anchor spec")
        .to_owned();
    let dead_port = wrong_spec
        .rsplit('/')
        .next()
        .expect("a port in the wrong spec")
        .to_owned();
    assert_ne!(
        real_port, dead_port,
        "the two specs must differ by address, or this gate measures nothing"
    );
    let started = std::time::Instant::now();
    let mut last = String::new();
    let followed = loop {
        if started.elapsed() > FOLLOW_PATIENCE {
            break false;
        }
        let (_, out, _) = vox(&data, &cfg, &["room", "invite", &room]);
        last = out.clone();
        if out.contains(&format!("/udp/{real_port}")) {
            break true;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    };

    assert!(
        followed,
        "the daemon never reached the anchor its configuration now names, after {:?}. It \
         started against {wrong_spec}, the file was rewritten to {real_spec} while it ran, \
         and an anchor spec may be a NAME precisely so it can move — a node that resolves \
         once holds the address it got at startup for ever. The invite said: {last:?}\n\
         daemon stderr: {:?}",
        started.elapsed(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default()
    );
}

/// The anchors file inside a config dir, as `Paths` lays it out.
fn anchors_file_for(cfg: &std::path::Path) -> std::path::PathBuf {
    cfg.join("anchors")
}
