//! **`vox status` shows what the node is doing, and its UDP flows each apart** — PRD-001 R35
//! (#84) and V030-34 (#383, ADR-022 6.9), driven through the shipped `vox` binary.
//!
//! **The staging — real processes only.** A `vox node` anchor on `[::]`, a host on IPv6 loopback
//! and a guest on IPv4 loopback (`support/world.rs`, `PathKind::Relayed`): the only path between
//! them is a circuit the anchor carries. The guest's leg to the anchor runs through a UDP proxy
//! the proof owns, which loses every 10th datagram once switched on — the relay leg drops what it
//! drops. The host serves a UDP sink and a TCP echo, trusts the guest, and is restarted as
//! `vox daemon --metrics 127.0.0.1:0`, so its counters are also served as Prometheus text.
//!
//! **#383: each UDP flow's counts, in `vox status --json` and the metrics.** The guest runs
//! `vox forward <sink>.<host>.<room>.vox` (a `<sink>/udp` service), opens the flow, and then
//! sends [`SENT`] numbered datagrams with the loss switched on. Asserted, against the flow's counts before the blast:
//! - the guest's `vox status --json` lists the flow, and its `to` grew by exactly [`SENT`] (`N`);
//! - the host's lists the guest's flow, and its `from` grew by exactly what the sink received:
//!   `N − M`, where `M` is what the relay leg lost, and `M > 0`;
//! - the host's metrics endpoint shows `vox_udp_flow_from_peer` for that flow equal to the
//!   host's status, and `vox_udp_flow_to_peer` / `vox_udp_flow_dropped` beside it.
//!
//! **#84: `vox status` (the person's form) lists** the room and its last sync, the guest as a
//! peer with its path (`relayed via` the anchor), the live tunnel a TCP connection through a
//! second forward holds, the UDP flow with its counts, and — once the guest stops — the trusted
//! member it can no longer reach, flagged `UNHEALTHY`.
//!
//! **#472 (ADR-028 K-1, L-9): the node's fingerprint, whole and grouped, with its art beside it.**
//! The host's `vox status` shows its fingerprint in groups of four, which read back as the
//! fingerprint `vox id` printed, beside a 5×5 mosaic of split triangles; the mosaic is the same
//! on a later `vox status`, and the guest's — another node, with the same local name `default` —
//! is a different one. Mutation: the art drawn from the node's name instead of its fingerprint —
//! red, PRODUCT (the two nodes draw the same art).
//!
//! **Every red names its side**: `PRODUCT`, `PRODUCT (staging)`, `APPARATUS` or `CANNOT MEASURE`.
//!
//! **Mutations that must turn it red, as PRODUCT:** the status report built with no UDP flows
//! (`udp_flows: Vec::new()` in `NodeActor::status_report`) — no flow listed; every peer reported
//! `direct` — no `relayed via`; `StatusReport::diagnose` finding nothing — no `UNHEALTHY`.
//!
//! It replaces `ops_status_proof`, deleted with the in-process gates (V29-17).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[cfg(feature = "test-knobs")]
#[path = "support/test_knobs.rs"]
mod test_knobs;

use world::attach as local_attach;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use world::{args, lossy_proxy, vox_once, PathKind, Setup, World};

/// Numbered datagrams sent with the relay leg's loss on.
const SENT: u64 = 300;
/// One every this long: slow enough that no local queue overflows (CLIENT_QUEUE), so every loss
/// is the relay leg's.
const EVERY: Duration = Duration::from_millis(10);

/// `vox status --json` of the node on `dir`, parsed.
fn status_json(dir: &std::path::Path, who: &str) -> Value {
    let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: {who}'s `vox status --json` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!("PRODUCT: {who}'s `vox status --json` is not JSON ({e}):\n{out}")
    })
}

/// `vox status` of the node on `dir`, as a person reads it.
fn status_text(dir: &std::path::Path, who: &str) -> String {
    let (ok, out, err) = vox_once(dir, &args(&["status"]));
    assert!(
        ok,
        "PRODUCT: {who}'s `vox status` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    out
}

/// Compiled source mutants identify themselves in the real daemon, not only the build log.
fn receipt_mutant_witness(snapshot: &Value, process: Option<&mut world::VoxProc>) {
    let output = process.map_or_else(
        || std::fs::read_to_string(snapshot["log_path"].as_str().unwrap_or("")).unwrap_or_default(),
        |process| process.transcript(),
    );
    if let Some(line) = output
        .lines()
        .find(|line| line.contains("RG7_MUTANT_ACTIVE "))
    {
        eprintln!("[proof] daemon witness: {line}");
    }
}

/// Give a wrong sustained-gap verdict its full grace period, without waiting on that verdict.
fn receipt_observation(dir: &std::path::Path, who: &str) -> Value {
    let first = status_json(dir, who);
    receipt_mutant_witness(&first, None);
    let start = first["now_ms"].as_u64().expect("APPARATUS: status clock");
    let threshold = first["not_receiving_after_ms"].as_u64().unwrap_or(60_000);
    let bound = Instant::now() + Duration::from_secs(180);
    loop {
        let current = status_json(dir, who);
        if current["now_ms"].as_u64().unwrap().saturating_sub(start) > threshold + 1_000 {
            return current;
        }
        assert!(
            Instant::now() < bound,
            "APPARATUS: {who}'s status clock did not cross its receipt threshold: {current}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The node card `vox status` prints under its first line: the art's rows (the leading run of
/// facet characters on each line), and the grouped fingerprint beside them, joined by spaces.
fn card(text: &str) -> (Vec<String>, String) {
    let facet = |c: char| matches!(c, '◢' | '◣' | '◤' | '◥');
    let mut art = Vec::new();
    let mut grouped = Vec::new();
    for line in text.lines().skip(1).take(5) {
        let line = line.trim();
        let row: String = line.chars().take_while(|c| facet(*c)).collect();
        if row.is_empty() {
            break;
        }
        let rest = line[row.len()..].trim();
        if !rest.is_empty() {
            grouped.push(rest.to_owned());
        }
        art.push(row);
    }
    (art, grouped.join(" "))
}

/// The UDP flow with `peer` for the service on `port`, in a status report: (to, from, dropped).
fn flow(report: &Value, peer: &str, port: u16) -> Option<(u64, u64, u64)> {
    report
        .get("udp_flows")?
        .as_array()?
        .iter()
        .find(|f| {
            f.get("peer").and_then(Value::as_str) == Some(peer)
                && f.get("service")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.contains(&port.to_string()))
        })
        .map(|f| {
            let n = |k: &str| f.get(k).and_then(Value::as_u64).unwrap_or(0);
            (n("to"), n("from"), n("dropped"))
        })
}

/// `GET /metrics` at `addr`: the body.
fn scrape(addr: &str) -> String {
    let mut s = TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("PRODUCT: nothing answers at the metrics address {addr}: {e}"));
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(format!("GET /metrics HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
        .unwrap_or_else(|e| panic!("PRODUCT: the metrics endpoint at {addr} took no request: {e}"));
    let mut got = String::new();
    s.read_to_string(&mut got)
        .unwrap_or_else(|e| panic!("PRODUCT: the metrics endpoint at {addr} did not answer: {e}"));
    got.split_once("\r\n\r\n")
        .map_or(got.clone(), |(_, body)| body.to_owned())
}

/// The value of `name{…peer="<peer>"…service="…<port>…"}` in Prometheus text.
fn metric(body: &str, name: &str, peer: &str, port: u16) -> Option<u64> {
    body.lines()
        .filter(|l| l.starts_with(&format!("{name}{{")))
        .find(|l| l.contains(&format!("peer=\"{peer}\"")) && l.contains(&port.to_string()))
        .and_then(|l| l.rsplit(' ').next()?.parse().ok())
}

/// A TCP echo on loopback: what the guest's second forward reaches, so a tunnel is live.
fn echo() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no TCP port for the echo: {e}"));
    let port = l.local_addr().map(|a| a.port()).unwrap_or_default();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// The same status journey, before its network scene: named nodes in the CLI, TUI and hook.
/// These commands have no auto-unlock wrapper; each observed state is the product's own.
fn node_command(dir: &std::path::Path, args: &[&str], input: &str) -> (bool, String, String) {
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_vox"))
        .args(args)
        .env("HOME", dir.join("home"))
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_TEST_KEYCHAIN", local_attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run the status journey's vox command");
    child
        .stdin
        .take()
        .expect("APPARATUS: piped input")
        .write_all(input.as_bytes())
        .expect("APPARATUS: give vox its command input");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

struct StatusNodes(tempfile::TempDir);
impl Drop for StatusNodes {
    fn drop(&mut self) {
        let _ = node_command(self.0.path(), &["daemon", "stop"], "");
    }
}

/// A real terminal screen, using the same portable-pty/vt100 apparatus as the wording journey.
struct StatusTui {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    input: Box<dyn Write + Send>,
    screen: Arc<Mutex<vt100::Parser>>,
}
impl Drop for StatusTui {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl StatusTui {
    fn start(dir: &std::path::Path, node: &str) -> Self {
        use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem as _};
        let pair = NativePtySystem::default()
            .openpty(PtySize {
                rows: 45,
                cols: 150,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("APPARATUS: open the status terminal");
        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_vox"));
        cmd.args(["tui", "--node", node, "--listen", "127.0.0.1:0"]);
        cmd.env("HOME", dir.join("home"));
        cmd.env("VOX_DATA_DIR", dir);
        cmd.env("VOX_CONFIG_DIR", dir.join("cfg"));
        cmd.env("VOX_TEST_KEYCHAIN", local_attach::keychain(dir));
        cmd.env("VOX_PROXY", "127.0.0.1:0");
        cmd.env("TERM", "xterm-256color");
        for name in [
            "VOX_NODE",
            "VOX_ROOM",
            "VOX_IDENTITY_PASSPHRASE",
            "VOX_ROOM_PASSPHRASE",
        ] {
            cmd.env_remove(name);
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("APPARATUS: start vox tui");
        drop(pair.slave);
        let input = pair
            .master
            .take_writer()
            .expect("APPARATUS: terminal input");
        let mut reader = pair
            .master
            .try_clone_reader()
            .expect("APPARATUS: terminal output");
        let screen = Arc::new(Mutex::new(vt100::Parser::new(45, 150, 0)));
        let sink = Arc::clone(&screen);
        std::thread::spawn(move || {
            let _master = pair.master;
            let mut buf = [0; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .expect("APPARATUS: screen lock")
                    .process(&buf[..n]);
            }
        });
        Self {
            child,
            input,
            screen,
        }
    }
    fn sees(&self, want: &str, matches: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let shown = self
                .screen
                .lock()
                .expect("APPARATUS: screen lock")
                .screen()
                .contents();
            if matches(&shown) {
                return shown;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: vox tui never showed {want}:\n{shown}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn ready_and_locked_are_the_states_a_person_sees() {
    let scratch = StatusNodes(tempfile::tempdir().expect("APPARATUS: status scratch root"));
    let dir = scratch.0.path();
    std::fs::create_dir_all(dir.join("home")).expect("APPARATUS: scratch HOME");
    let run = |args: &[&str], input: &str| {
        let (ok, out, err) = node_command(dir, args, input);
        assert!(ok, "PRODUCT: vox {args:?} failed: {out}{err}");
        format!("{out}{err}")
    };
    run(
        &["node", "create", "private", "--passphrase-file", "-"],
        "private passphrase\n",
    );
    let created = run(
        &[
            "node",
            "create",
            "free",
            "--passphrase-file",
            "-",
            "--listen",
            "127.0.0.1:0",
        ],
        "\n",
    );
    assert!(
        created.contains("Ready"),
        "PRODUCT: a no-passphrase node was not made Ready: {created}"
    );
    let listed = run(&["node", "list"], "");
    let row = |text: &str, name: &str, status: &str| {
        text.lines()
            .any(|l| l.split_whitespace().next() == Some(name) && l.contains(status))
    };
    assert!(row(&listed, "private", "Locked") && row(&listed, "free", "Ready"),
        "PRODUCT: node list must show protected private Locked and passphrase-free free Ready: {listed}");
    for (node, want) in [("private", "Locked"), ("free", "Ready")] {
        let (ok, json, err) = node_command(dir, &["status", "--node", node, "--json"], "");
        assert!(ok, "PRODUCT: {node} status failed: {json}{err}");
        let json: Value = serde_json::from_str(&json).expect("PRODUCT: status was not JSON");
        assert_eq!(
            json["status"], want,
            "PRODUCT: {node}'s JSON status must be {want}: {json}"
        );
        let text = run(&["status", "--node", node], "");
        assert!(
            text.contains(want),
            "PRODUCT: {node}'s text status must say {want}: {text}"
        );
    }
    let turn =
        serde_json::json!({"session_id":"locked-status", "cwd":dir.join("home")}).to_string();
    let hook = run(
        &["agent", "hook", "--node", "private", "--format", "text"],
        &turn,
    );
    assert!(
        hook.contains("private is Locked") && hook.contains("vox node unlock -- private"),
        "PRODUCT: a hook on a Locked node must say Locked and how to unlock: {hook}"
    );
    let tui = StatusTui::start(dir, "free");
    let screen = tui.sees("free Ready and private Locked", |t| {
        t.contains("free  Ready") && t.contains("private  Locked")
    });
    assert!(
        !screen.contains("Unlock node"),
        "PRODUCT: a passphrase-free node asked to unlock: {screen}"
    );
    for action in ["lock", "forget-passphrase"] {
        let out = run(&["node", action, "free"], "");
        assert!(
            !out.contains("Locked"),
            "PRODUCT: {action} falsely called a passphrase-free node Locked: {out}"
        );
        let listed = run(&["node", "list"], "");
        assert!(
            row(&listed, "free", "Ready"),
            "PRODUCT: {action} stopped the passphrase-free node: {listed}"
        );
    }
    drop(tui);
    #[allow(unused_mut)]
    let mut tui = StatusTui::start(dir, "private");
    tui.sees("Unlock node for the Locked node", |t| {
        t.contains("Unlock node") && t.contains("private  Locked")
    });
    // macOS has the existing Keychain in which a typed TUI unlock can be remembered.
    #[cfg(target_os = "macos")]
    {
        tui.input
            .write_all(b"private passphrase\r")
            .and_then(|()| tui.input.flush())
            .expect("APPARATUS: type the node's passphrase into the TUI");
        tui.sees("private Ready after TUI Unlock", |t| {
            t.contains("private  Ready") && !t.contains("Unlock node")
        });
        let listed = run(&["node", "list"], "");
        assert!(
            row(&listed, "private", "Ready")
                && listed
                    .lines()
                    .any(|l| l.contains("private") && l.contains("(remembered)")),
            "PRODUCT: TUI Unlock did not make and remember private Ready: {listed}"
        );
    }
    drop(tui);
    let locked = run(&["node", "lock", "private"], "");
    assert!(
        locked.contains("private is Locked and forgotten"),
        "PRODUCT: protected Lock did not say its resulting state: {locked}"
    );
    eprintln!("[proof] Ready/Locked in CLI status/list, TUI and hook; no-passphrase Lock/Forget stayed Ready");
}

/// An unrelated unavailable machine inventory cannot erase a selected node's status (#960).
#[test]
#[ignore = "real binaries and production Argon2id; run in release"]
fn status_survives_another_nodes_unavailable_anchor_inventory() {
    watchdog::arm();
    let scratch = StatusNodes(tempfile::tempdir().expect("APPARATUS: status scratch root"));
    let dir = scratch.0.path();
    std::fs::create_dir_all(dir.join("home")).expect("APPARATUS: scratch HOME");
    let run = |args: &[&str], input: &str| {
        let (ok, out, err) = node_command(dir, args, input);
        assert!(ok, "PRODUCT: vox {args:?} failed: {out}{err}");
        out
    };
    for name in ["private", "broken-status-witness"] {
        run(
            &["node", "create", name, "--passphrase-file", "-"],
            "private passphrase\n",
        );
    }
    run(
        &[
            "node",
            "create",
            "free",
            "--passphrase-file",
            "-",
            "--listen",
            "127.0.0.1:0",
        ],
        "\n",
    );
    // Test-side apparatus: a detached node's unsupported display cache elicits the same
    // machine-inventory refusal as an attached room without its observation. No authority
    // state is changed, and every verdict below comes from the real vox command.
    let cache = dir.join("nodes/broken-status-witness/anchor-inventory.cbor");
    std::fs::write(&cache, [0x82, 0x00, 0x80])
        .expect("APPARATUS: stage unsupported scratch inventory");
    let (ok, out, err) = node_command(dir, &["anchor", "list"], "");
    assert!(
        !ok && format!("{out}{err}").contains("broken-status-witness"),
        "APPARATUS: unavailable inventory staging was not observable: {out}{err}"
    );
    for (node, want) in [("free", "Ready"), ("private", "Locked")] {
        let out = run(&["status", "--node", node, "--json"], "");
        let report: Value = serde_json::from_str(&out).expect("PRODUCT: status was not JSON");
        assert_eq!(
            report["status"], want,
            "PRODUCT: inventory refusal erased {node}'s status: {report}"
        );
        assert!(
            report.get("anchors") == Some(&Value::Null)
                && report["anchor_inventory_error"]
                    .as_str()
                    .is_some_and(|e| e.contains("broken-status-witness")),
            "PRODUCT: unavailable inventory looked complete or lost its cause: {report}"
        );
        let text = run(&["status", "--node", node], "");
        assert!(
            text.contains(want)
                && text.contains("broken-status-witness")
                && !text.contains("healthy: nothing needs attention"),
            "PRODUCT: status hid its inventory refusal or claimed unqualified health: {text}"
        );
    }
    let (ok, out, err) = node_command(dir, &["anchor", "list"], "");
    assert!(
        !ok && format!("{out}{err}").contains("broken-status-witness"),
        "PRODUCT: anchor list silently accepted incomplete inventory: {out}{err}"
    );
    // Repair only the disposable display cache, without restarting or unlocking anything.
    std::fs::write(&cache, [0x82, 0x01, 0x80]).expect("APPARATUS: repair scratch inventory");
    run(&["anchor", "list"], "");
    for (node, want) in [("free", "Ready"), ("private", "Locked")] {
        let out = run(&["status", "--node", node, "--json"], "");
        let report: Value = serde_json::from_str(&out).expect("PRODUCT: status was not JSON");
        assert!(
            report["status"] == want
                && report["anchors"].is_array()
                && report.get("anchor_inventory_error").is_none(),
            "PRODUCT: repaired inventory did not recover without restart: {report}"
        );
    }
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; run in release"]
fn vox_status_shows_rooms_peers_tunnels_udp_flows_and_what_is_unhealthy() {
    watchdog::arm();
    ready_and_locked_are_the_states_a_person_sees();
    // ---- the sink: counts each numbered datagram it receives ----
    let sink = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no UDP port for the sink: {e}"));
    let sink_port = sink.local_addr().map(|a| a.port()).unwrap_or_default();
    let received = Arc::new(AtomicU64::new(0));
    {
        let received = Arc::clone(&received);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = sink.recv_from(&mut buf) {
                if n >= 4 {
                    received.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
    let echo_port = echo();
    type Knob = Option<(Arc<AtomicU64>, Arc<AtomicU64>)>;
    let lossy: Arc<Mutex<Knob>> = Arc::default();
    let lossy_in = Arc::clone(&lossy);
    let mut w = World::build(&Setup {
        specs: vec![
            format!("{sink_port}={sink_port}/udp"),
            format!("{echo_port}={echo_port}"),
        ],
        trusted: true,
        path: PathKind::Relayed,
        guest_leg: Some(Box::new(move |anchor| {
            let (addr, dropped, knob, _) = lossy_proxy(anchor, Duration::ZERO);
            *lossy_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((dropped, knob));
            Some(addr)
        })),
    });
    w.restart_host_as_daemon_with(&["--metrics", "127.0.0.1:0"]);
    let metrics_at = w
        .host
        .as_mut()
        .map(world::VoxProc::transcript)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("vox daemon: metrics http://"))
        .map(|a| a.trim_end_matches("/metrics").to_owned())
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): the host's `vox daemon --metrics` never said where it serves"
            )
        });
    let guest = w.guest_dir.clone();
    let host = w.host_dir.clone();
    // The share probed the sink once (ADR-028 S-2), before `vox serve` printed its room: that
    // datagram never crossed a forward, so the count starts after it.
    let probed = received.load(Ordering::SeqCst);

    // ---- open the UDP flow, the loss still off ----
    let (mut fwd, at) = w.forward_service("udp-forward", &guest, &format!("{sink_port}/udp"));
    let client = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no UDP port for the client: {e}"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while received.load(Ordering::SeqCst) == probed && Instant::now() < deadline {
        let _ = client.send_to(&0u32.to_be_bytes(), at);
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        received.load(Ordering::SeqCst) > probed,
        "PRODUCT (staging): no datagram crossed the UDP forward in 120 s.\nthe forward said:\n{}",
        fwd.transcript()
    );
    std::thread::sleep(Duration::from_secs(1));

    // ---- the counts before, then N numbered datagrams with the relay leg losing every 10th ----
    let guest_before = flow(&status_json(&guest, "the guest"), &w.host_fp, sink_port);
    let host_before = flow(&status_json(&host, "the host"), &w.guest_fp, sink_port);
    let (Some(guest_before), Some(host_before)) = (guest_before, host_before) else {
        panic!(
            "PRODUCT: a UDP flow is carrying datagrams, yet `vox status --json` does not list it: \
             the guest's flow to the host {guest_before:?}, the host's from the guest \
             {host_before:?}.\nguest:\n{}\nhost:\n{}",
            status_json(&guest, "the guest"),
            status_json(&host, "the host")
        );
    };
    let sink_before = received.load(Ordering::SeqCst);
    let (leg_dropped, knob) = lossy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| panic!("APPARATUS: the lossy relay leg was never built"));
    let leg_before = leg_dropped.load(Ordering::SeqCst);
    knob.store(10, Ordering::SeqCst);
    let start = Instant::now();
    for seq in 1..=SENT {
        let mut d = u32::try_from(seq)
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        d.resize(200, 0);
        client
            .send_to(&d, at)
            .unwrap_or_else(|e| panic!("APPARATUS: the client could not send datagram {seq}: {e}"));
        let next = start + EVERY * u32::try_from(seq).unwrap_or(u32::MAX);
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    knob.store(0, Ordering::SeqCst);
    let arrived = received.load(Ordering::SeqCst) - sink_before;
    let leg_lost = leg_dropped.load(Ordering::SeqCst) - leg_before;

    let guest_report = status_json(&guest, "the guest");
    let host_report = status_json(&host, "the host");
    let guest_after = flow(&guest_report, &w.host_fp, sink_port);
    let host_after = flow(&host_report, &w.guest_fp, sink_port);
    let body = scrape(&metrics_at);
    let m_from = metric(&body, "vox_udp_flow_from_peer", &w.guest_fp, sink_port);
    let m_to = metric(&body, "vox_udp_flow_to_peer", &w.guest_fp, sink_port);
    let m_dropped = metric(&body, "vox_udp_flow_dropped", &w.guest_fp, sink_port);
    eprintln!(
        "[proof] sent {SENT}; the sink received {arrived}; the relay leg dropped {leg_lost} packet(s). \
         guest flow before {guest_before:?} after {guest_after:?}; host flow before {host_before:?} \
         after {host_after:?}; host metrics to {m_to:?} from {m_from:?} dropped {m_dropped:?}"
    );
    let (Some(guest_after), Some(host_after)) = (guest_after, host_after) else {
        panic!(
            "PRODUCT: the UDP flow left `vox status --json` while it was live: guest \
             {guest_after:?}, host {host_after:?}.\nguest:\n{guest_report}\nhost:\n{host_report}"
        );
    };
    let lost = SENT.saturating_sub(arrived);
    assert!(
        lost > 0,
        "CANNOT MEASURE: the relay leg dropped {leg_lost} packet(s), none of them a datagram the \
         sink was waiting for ({arrived} of {SENT} arrived), so no M to show"
    );
    assert!(
        guest_after.0 - guest_before.0 == SENT,
        "PRODUCT: the guest sent {SENT} datagrams on the flow, yet its `vox status --json` counts \
         {} more `to` ({guest_before:?} → {guest_after:?})",
        guest_after.0 - guest_before.0
    );
    assert!(
        host_after.1 - host_before.1 == arrived,
        "PRODUCT: {arrived} of {SENT} datagrams reached the service ({lost} lost at the relay), yet \
         the host's `vox status --json` counts {} more `from` ({host_before:?} → {host_after:?})",
        host_after.1 - host_before.1
    );
    assert!(
        m_from == Some(host_after.1) && m_to.is_some() && m_dropped.is_some(),
        "PRODUCT: the host's metrics endpoint must show the flow's counts as its status does \
         (from {}): to {m_to:?}, from {m_from:?}, dropped {m_dropped:?}.\n{body}",
        host_after.1
    );

    // ---- #84: the person's `vox status`, first with the UDP flow live ----
    let text = status_text(&host, "the host");
    eprintln!("[proof] the host's `vox status` with the UDP flow live:\n{text}");
    let (host_art, host_grouped) = card(&text);
    let guest_text = status_text(&guest, "the guest");
    let (guest_art, _) = card(&guest_text);
    let groups: Vec<String> = w
        .host_fp
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|g| g.iter().collect())
        .collect();
    eprintln!(
        "[proof] the host's card: {host_art:?} {host_grouped:?}; the guest's art: {guest_art:?}"
    );
    assert!(
        host_grouped == groups.join(" ")
            && host_art.len() == 5
            && host_art.iter().all(|r| r.chars().count() == 10),
        "PRODUCT: the host's `vox status` must show its fingerprint {} in groups of four beside \
         a 5×5 mosaic; it showed {host_grouped:?} beside {host_art:?}:\n{text}",
        w.host_fp
    );
    assert!(
        guest_art.len() == 5 && guest_art != host_art,
        "PRODUCT: the guest is another node, so its `vox status` must draw other art than the \
         host's {host_art:?}; it drew {guest_art:?}:\n{guest_text}"
    );
    let g = &w.guest_fp[..12];
    let anchor_short = w
        .host_anchor
        .split('@')
        .next()
        .map(|a| a[..12.min(a.len())].to_owned())
        .unwrap_or_default();
    let room_short = &w.room[..12];
    let mut missing = Vec::new();
    let room_line = text
        .lines()
        .find(|l| l.trim_start().starts_with(room_short) && l.contains("last sync"));
    if room_line.is_none_or(|l| l.contains("last sync never")) {
        missing.push(format!(
            "the room {room_short} with a last sync (line: {room_line:?})"
        ));
    }
    if !text.lines().any(|l| {
        l.trim_start().starts_with(g) && l.contains(&format!("relayed via {anchor_short}"))
    }) {
        missing.push(format!(
            "the guest {g} as a peer, relayed via {anchor_short}"
        ));
    }
    if !text.lines().any(|l| {
        l.contains(&sink_port.to_string())
            && l.contains(&format!("with {g}"))
            && l.contains(&format!("from {}", host_after.1))
    }) {
        missing.push(format!(
            "the UDP flow with {g} on {sink_port}, from {}",
            host_after.1
        ));
    }
    assert!(
        missing.is_empty(),
        "PRODUCT: the host's `vox status` does not show {}.\n{text}",
        missing.join("; ")
    );
    assert!(
        text.contains("healthy: nothing needs attention"),
        "PRODUCT: with its guest connected and synced, the host's `vox status` flags something:\n{text}"
    );

    // ---- then with a TCP tunnel live: one vox holds a profile, so the UDP forward goes first ----
    drop(fwd);
    let (tcp_fwd, tcp_at) = w.forward_service("tcp-forward", &guest, &echo_port.to_string());
    let mut held = TcpStream::connect(tcp_at)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the TCP forward took no connection: {e}"));
    held.set_read_timeout(Some(Duration::from_secs(60))).ok();
    held.write_all(b"held")
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the TCP forward took no bytes: {e}"));
    let mut back = [0u8; 4];
    held.read_exact(&mut back)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): no echo through the TCP forward: {e}"));
    let text = status_text(&host, "the host");
    eprintln!("[proof] the host's `vox status` with a TCP tunnel live:\n{text}");
    let (again, _) = card(&text);
    assert!(
        again == host_art,
        "PRODUCT: the same node must draw the same art every time: first {host_art:?}, now \
         {again:?}"
    );
    assert!(
        text.lines()
            .any(|l| l.starts_with("tunnel ") && l.contains(&format!("from {g}"))),
        "PRODUCT: a TCP connection from the guest {g} is live through the host, yet the host's \
         `vox status` lists no tunnel from it:\n{text}"
    );

    // ---- the guest goes away: the trusted member it cannot reach is flagged ----
    drop(held);
    drop(tcp_fwd);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = status_text(&host, "the host");
        if text.contains("UNHEALTHY:") {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!("[proof] the host's `vox status` with the guest gone:\n{text}");
    assert!(
        text.contains("UNHEALTHY:")
            && text
                .lines()
                .any(|l| l.contains(&format!("trusted member {g} unreachable"))),
        "PRODUCT: the host's trusted guest {g} went away, yet in 120 s `vox status` never flagged \
         it unreachable:\n{text}"
    );
}

/// Absence of a received consent is a local observation, not a remote trust decision.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries and production Argon2id; run in release"]
fn status_journey_does_not_blame_missing_history_on_remote_trust() {
    watchdog::arm();
    let sink = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: service port");
    test_knobs::require(&["VOX_TEST_UNAVAILABLE_HEAD_FILE"]);
    let mut w = World::new(
        sink.local_addr()
            .expect("APPARATUS: service address")
            .port(),
        false,
    );
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    let (ok, out, err) = vox_once(
        &w.guest_dir,
        &args(&["trust", "add", &w.host_fp, "--name", "author"]),
    );
    assert!(ok, "PRODUCT: reader could not trust author: {out}{err}");
    let report = loop {
        let (_, out, err) = vox_once(
            &w.guest_dir,
            &args(&["agent", "doctor", "--room", &w.room, "--json"]),
        );
        let report: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("PRODUCT: doctor printed invalid JSON ({e}): {out}{err}"));
        let ready = report["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|check| {
                check["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.starts_with("you trust it"))
            });
        if ready {
            break report;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("[proof] doctor without received consent: {report}");
    let text = report.to_string();
    assert!(
        text.contains("your node has not received its trust for you")
            && !text.contains("has not trusted you")
            && text.contains("if its operator has not accepted your fingerprint")
            && text.contains("ask its operator to accept your fingerprint"),
        "PRODUCT: doctor must offer acceptance for a never-trusted reader without inventing a remote decision: {report}"
    );

    // Accept on the author's real daemon while it refuses to serve its new consent to
    // the reader. Local trust and received room consent are deliberately distinct.
    drop(w.host.take());
    world::reap_daemon(&w.host_dir);
    let marker = w.tmp.path().join("withheld-consent");
    std::fs::write(&marker, format!("{} {}\n", w.host_fp, w.guest_fp))
        .expect("APPARATUS: withhold consent history");
    let pass = w.tmp.path().join("consent-passphrases");
    std::fs::write(&pass, format!("{}\n{}\n", world::IDENTITY, w.passphrase))
        .expect("APPARATUS: daemon passphrase file");
    let mut author = world::VoxProc::spawn_env(
        "accepting-author",
        &w.host_dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            &world::utf8(&pass),
            "--anchor",
            &w.host_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[("VOX_TEST_UNAVAILABLE_HEAD_FILE", &world::utf8(&marker))],
    );
    author.expect_line("author's room open", |line| {
        line.starts_with("vox daemon: holding room") && line.contains(&w.room)
    });
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &w.guest_fp, "--name", "accepted-reader"]),
    );
    assert!(ok, "APPARATUS: author could not accept reader: {out}{err}");
    let (ok, accepted, err) = vox_once(&w.host_dir, &args(&["trust", "list"]));
    assert!(
        ok && accepted.contains(&w.guest_fp),
        "APPARATUS: author's accepted reader was not listed: {accepted}{err}"
    );
    let (_, out, err) = vox_once(
        &w.guest_dir,
        &args(&["agent", "doctor", "--room", &w.room, "--json"]),
    );
    let pending: Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: pending-consent doctor JSON ({e}): {out}{err}"));
    eprintln!("[proof] author accepted reader, consent not received: {pending}");
    let text = pending.to_string();
    assert!(
        text.contains("your node has not received its trust for you")
            && !text.contains("has not trusted you")
            && text.contains("otherwise check vox status"),
        "PRODUCT: doctor blamed an operator who already accepted the reader instead of separating missing consent from trust: {pending}"
    );
    drop(author);
}

/// A feed can advance without a message: reading, key/policy changes and expiry are not loss.
#[test]
#[ignore = "real daemons and read receipts; run in release"]
fn non_message_feed_entries_and_expired_messages_do_not_report_missing_history() {
    use vox_core::node::ipc::{Frame, Request};
    watchdog::arm();
    let sink = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: service socket");
    let w = World::new(
        sink.local_addr()
            .expect("APPARATUS: service address")
            .port(),
        true,
    );
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    let (ok, out, err) = vox_once(
        &w.guest_dir,
        &args(&["trust", "add", &w.host_fp, "--name", "author"]),
    );
    assert!(ok, "APPARATUS: reader trusts author: {out}{err}");
    let cid = vox_core::node::link::b32_decode(&w.room, "proof room").expect("APPARATUS: room id");
    let rt = tokio::runtime::Runtime::new().expect("APPARATUS: IPC runtime");
    rt.block_on(async {
        let mut poster = local_attach::node_client(&w.host_dir, "default")
            .await
            .expect("APPARATUS: author's socket");
        let mut reader = local_attach::node_client(&w.guest_dir, "default")
            .await
            .expect("APPARATUS: reader's socket");
        for n in 0..25 {
            let text = format!("read-only-receipt-{n:02}");
            let reply = poster
                .request(&Request::Post {
                    channel_id: cid,
                    text: text.clone(),
                    card: false,
                })
                .await;
            assert!(
                matches!(reply, Ok(Frame::Ok)),
                "APPARATUS: author could not post receipt staging: {reply:?}"
            );
            let entry = loop {
                let reply = reader
                    .request(&Request::RoomPage {
                        channel_id: cid,
                        before: None,
                        limit: 0,
                    })
                    .await;
                if let Ok(Frame::RoomPage { rows, .. }) = reply {
                    if let Some(row) = rows.iter().find(|r| r.text == text) {
                        break row.entry_hash;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let current = status_json(&w.guest_dir, "reader");
            let member = current["rooms"][0]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["me"] == true)
                .unwrap();
            // Before RG-7 this same header fact was serialized as holds_through.
            let before = member["verified_through"]
                .as_u64()
                .or_else(|| member["holds_through"].as_u64())
                .unwrap_or(0);
            let reply = reader
                .request(&Request::MarkRead {
                    channel_id: cid,
                    entries: vec![entry],
                })
                .await;
            assert!(
                matches!(reply, Ok(Frame::Ok)),
                "APPARATUS: mark a shown message read: {reply:?}"
            );
            loop {
                let current = status_json(&w.guest_dir, "reader");
                let member = current["rooms"][0]["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|m| m["me"] == true)
                    .unwrap();
                let head = member["verified_through"]
                    .as_u64()
                    .or_else(|| member["holds_through"].as_u64())
                    .unwrap_or(0);
                if head > before {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });
    let current = status_json(&w.guest_dir, "reader");
    let member = current["rooms"][0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["me"] == true)
        .unwrap();
    let reader_head = member["verified_through"]
        .as_u64()
        .or_else(|| member["holds_through"].as_u64())
        .expect("APPARATUS: reader feed head");
    loop {
        let current = status_json(&w.host_dir, "poster");
        let member = current["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == w.guest_fp)
            .unwrap();
        if member["connected"] == true
            && member["verified_through"]
                .as_u64()
                .or_else(|| member["holds_through"].as_u64())
                .unwrap_or(0)
                >= reader_head
            && member["advertised_through"].as_u64().unwrap_or(reader_head) >= reader_head
        {
            assert!(
                reader_head >= 25,
                "APPARATUS: fewer than twenty receipt entries: {current}"
            );
            receipt_observation(&w.host_dir, "fully received read receipts");
            let text = status_text(&w.host_dir, "poster");
            eprintln!(
                "[proof] twenty-five received read receipts, zero reader posts:\n{text}\n{current}"
            );
            assert!(!text.contains("not receiving") && text.contains("healthy: nothing needs attention"),
                "PRODUCT: a connected member only read; every feed entry is held, but status called it unhealthy:\n{text}");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Governance entries have no shown message position either.
    let change = |argv: &[&str]| loop {
        let (ok, out, err) = vox_once(&w.host_dir, &args(argv));
        if ok {
            break;
        }
        // A refused, unchanged request is safe to stage again after the earlier change.
        assert!(
            (out.contains("a previous change to this room is still being applied")
                || err.contains("a previous change to this room is still being applied"))
                && (out.contains("this request made no change")
                    || err.contains("this request made no change")),
            "APPARATUS: staging room change {argv:?} failed: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    for n in 0..25 {
        change(&["room", "rename", &w.room, &format!("policy-only-{n:02}")]);
    }
    change(&["room", "retention", &w.room, "1"]);
    loop {
        let current = status_json(&w.guest_dir, "reader");
        let member = current["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == w.host_fp)
            .unwrap();
        let advertised = member["advertised_through"].as_u64().unwrap_or(0);
        let verified = member["verified_through"].as_u64().unwrap_or(0);
        let shown = member["holds_through"].as_u64().unwrap_or(0);
        if member["connected"] == true && advertised >= shown + 20 && verified >= advertised {
            let current = receipt_observation(&w.guest_dir, "fully received policy/expiry entries");
            let member = current["rooms"][0]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|member| member["id"] == w.host_fp)
                .unwrap();
            let text = status_text(&w.guest_dir, "reader");
            eprintln!("[proof] governance/expired feed entries all held:\n{text}\n{current}");
            assert!(!text.contains("not receiving"),
                "PRODUCT: twenty-five policy entries were all held, but status reports missing history:\n{text}");
            if current["rooms"][0]["retention"] == 1 && member["holds_through"].is_null() {
                let read = vox_once(&w.guest_dir, &args(&["room", "read", &w.room, "--json"])).1;
                assert!(
                    !read.contains("read-only-receipt-"),
                    "APPARATUS: messages not expired: {read}"
                );
                assert!(text.contains("healthy: nothing needs attention"),
                    "PRODUCT: a quiet connected member with expired messages reads unhealthy:\n{text}");
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "real binaries and a sparse 180-post room; run in release"]
fn a_newcomer_with_the_live_window_does_not_owe_the_archive_in_status() {
    sparse_live_window_reads_healthy(WindowScene::Newcomer);
}

#[test]
#[ignore = "real binaries and an offline reader across 180 posts; run in release"]
fn an_offline_reader_caught_up_to_the_live_window_reads_healthy() {
    sparse_live_window_reads_healthy(WindowScene::Offline);
}

enum WindowScene {
    Newcomer,
    Offline,
}

/// No history is ever requested. A newcomer shows every post in the newest 128 feed positions
/// and never the archive below them; a reader that was away while the posts were made owes every
/// one of them from where it already held, and shows all of them unasked, newest first (ADR-052
/// RG-6, ADR-053 MP-12, ADR-054 PL-3). The verdict is the reader's real status, after it shows
/// that and its status clock crosses the receipt threshold.
fn sparse_live_window_reads_healthy(scene: WindowScene) {
    let offline = matches!(scene, WindowScene::Offline);
    use vox_core::node::ipc::{Frame, Request};
    struct ReaderDaemon<'a>(&'a std::path::Path);
    impl Drop for ReaderDaemon<'_> {
        fn drop(&mut self) {
            world::reap_daemon(self.0);
        }
    }
    watchdog::arm();
    let sink = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: service socket");
    let w = World::new(sink.local_addr().expect("APPARATUS: address").port(), true);
    let reader = if offline {
        w.guest_dir.clone()
    } else {
        let dir = w.tmp.path().join("newcomer");
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: newcomer profile");
        dir
    };
    let _reader_daemon = ReaderDaemon(&reader);
    let (ok, out, err) = vox_once(&reader, &args(&["id"]));
    assert!(ok, "APPARATUS: reader identity: {out}{err}");
    let reader_id = out.trim().to_owned();
    local_attach::Root::at(&reader, world::IDENTITY).attach("default");
    for (dir, peer, name) in [
        (&reader, &w.host_fp, "author"),
        (&w.host_dir, &reader_id, "reader"),
    ] {
        let (ok, out, err) = vox_once(dir, &args(&["trust", "add", peer, "--name", name]));
        assert!(ok, "APPARATUS: prepare reader trust: {out}{err}");
    }
    world::reap_daemon(&reader);
    let cid = vox_core::node::link::b32_decode(&w.room, "proof room").expect("APPARATUS: room id");
    let rt = tokio::runtime::Runtime::new().expect("APPARATUS: runtime");
    rt.block_on(async {
        let mut author = local_attach::node_client(&w.host_dir, "default")
            .await
            .expect("APPARATUS: author's socket");
        for number in 0..180 {
            let reply = author
                .request(&Request::Post {
                    channel_id: cid,
                    text: format!("live-window-post-{number:03}"),
                    card: false,
                })
                .await;
            assert!(
                matches!(reply, Ok(Frame::Ok)),
                "APPARATUS: author could not post {number}: {reply:?}"
            );
        }
    });
    let source = status_json(&w.host_dir, "author");
    let head = source["rooms"][0]["own_feed_through"]
        .as_u64()
        .expect("APPARATUS: author's feed head");
    assert!(
        head > 149,
        "APPARATUS: feed does not cross the sparse window: {source}"
    );
    let mut restarted = None;
    if offline {
        let pass = w.tmp.path().join("offline-reader-passphrases");
        std::fs::write(&pass, format!("{}\n{}\n", world::IDENTITY, w.passphrase))
            .expect("APPARATUS: reader passphrases");
        let mut process = world::VoxProc::spawn_env(
            "returned-reader",
            &reader,
            &args(&[
                "daemon",
                "--passphrase-file",
                &world::utf8(&pass),
                "--anchor",
                &w.guest_anchor,
                "--listen",
                "127.0.0.1:0",
            ]),
            &[],
        );
        process.expect_line("reader daemon ready", |line| {
            line.contains("holding room") && line.contains(&w.room)
        });
        restarted = Some(process);
    }
    if !offline {
        let (ok, _, out, err) = w.join(&reader);
        assert!(ok, "APPARATUS: newcomer did not join: {out}{err}");
    }
    local_attach::Root::at(&reader, world::IDENTITY).attach("default");
    let snapshot = loop {
        let (ok, read, err) = vox_once(&reader, &args(&["room", "read", &w.room, "--json"]));
        assert!(ok, "PRODUCT: live-window read failed: {read}{err}");
        let snapshot = status_json(&reader, "sparse reader");
        let advertised = snapshot["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == w.host_fp)
            .and_then(|member| member["advertised_through"].as_u64())
            .unwrap_or(head);
        // The 180 consecutive posts end at `head`: post 52 starts its newest 128 entries.
        // A newcomer can make the author append a key package, moving that floor forward.
        // A reader that was away owes all 180.
        let first_post = if offline {
            0
        } else {
            52 + advertised.saturating_sub(head) as usize
        };
        let shown =
            (first_post..180).all(|number| read.contains(&format!("live-window-post-{number:03}")));
        if shown {
            assert!(
                offline || !read.contains("live-window-post-000"),
                "APPARATUS: the on-demand archive was fetched without being requested: {read}"
            );
            break snapshot;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if !offline {
        let member = snapshot["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == w.host_fp)
            .unwrap();
        assert!(
            member["verified_through"].as_u64().unwrap_or(0) < head.saturating_sub(128),
            "APPARATUS: the reader has no deliberate contiguous archive gap: {member}"
        );
    }
    receipt_mutant_witness(&snapshot, restarted.as_mut());
    receipt_observation(&reader, "fully received live window");
    let text = status_text(&reader, "sparse reader");
    eprintln!("[proof] offline={offline}, author's feed head={head}, every post owed shown, none requested:\n{text}\n{snapshot}");
    assert!(!text.contains("not receiving") && text.contains("healthy: nothing needs attention"),
        "PRODUCT: reader offline={offline} holds its live window, but status counts the unrequested archive as missing:\n{text}");
    drop(restarted);
}

/// RG-13: disk usage belongs to the whole account, not only its selected Ready node.
#[test]
#[ignore = "real binary, two scratch stores and production Argon2id; run in release with test-knobs"]
fn status_shows_every_store_and_its_filesystems_free_bytes() {
    use vox_core::node::paths::{NodeName, Paths};
    watchdog::arm();
    let scratch = StatusNodes(tempfile::tempdir().expect("APPARATUS: store-size profile"));
    let dir = scratch.0.path();
    std::fs::create_dir_all(dir.join("home")).unwrap();
    let run = |args: &[&str], input: &str| {
        let (ok, out, err) = node_command(dir, args, input);
        assert!(ok, "APPARATUS: vox {args:?}: {out}{err}");
        out
    };
    run(
        &[
            "node",
            "create",
            "small",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            "-",
        ],
        "\n",
    );
    run(
        &[
            "node",
            "create",
            "large",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            "-",
        ],
        "large secret\n",
    );
    run(
        &["node", "unlock", "large", "--passphrase-file", "-"],
        "large secret\n",
    );
    run(
        &[
            "room",
            "create",
            "--node",
            "large",
            "--name",
            "large-room",
            "--passphrase-file",
            "-",
        ],
        "room secret\n",
    );
    for n in 0..8 {
        run(
            &[
                "room",
                "post",
                "--node",
                "large",
                "large-room",
                &format!("store-size-{n}-{}", "x".repeat(4096)),
            ],
            "",
        );
    }
    run(&["node", "lock", "large"], "");
    let locked = run(&["status", "--node", "large", "--json"], "");
    let locked: Value = serde_json::from_str(&locked).unwrap();
    assert_eq!(
        locked["status"], "Locked",
        "APPARATUS: large store is not Locked: {locked}"
    );
    let account = Paths::resolve("small", Some(dir), Some(&dir.join("cfg")))
        .unwrap()
        .account();
    let stores: Vec<_> = ["small", "large"]
        .into_iter()
        .map(|name| {
            let path = account
                .node_paths_as_they_are(&NodeName::parse(name).unwrap())
                .store_file();
            (name, path)
        })
        .collect();
    let lengths: Vec<_> = stores
        .iter()
        .map(|(_, p)| std::fs::metadata(p).unwrap().len())
        .collect();
    assert_ne!(
        lengths[0], lengths[1],
        "APPARATUS: distinct store sizes were not staged"
    );
    let free = |path: &std::path::Path| {
        let stat = rustix::fs::statvfs(path).expect("APPARATUS: fresh OS free-space sample");
        #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
        let unit = u64::try_from(stat.f_frsize).unwrap();
        stat.f_bavail.saturating_mul(unit)
    };
    for selected in ["small", "large"] {
        let before: Vec<_> = stores.iter().map(|(_, p)| free(p)).collect();
        let out = run(&["status", "--node", selected, "--json"], "");
        let report: Value = serde_json::from_str(&out).expect("PRODUCT: status JSON");
        let rows = report["stores"].as_array().unwrap_or_else(|| {
            panic!(
                "PRODUCT: status must report all account stores, including Locked large: {report}"
            )
        });
        assert_eq!(
            rows.len(),
            2,
            "PRODUCT: selected {selected} omitted an account store: {report}"
        );
        for (index, (name, path)) in stores.iter().enumerate() {
            let row = rows
                .iter()
                .find(|row| row["node"] == *name)
                .unwrap_or_else(|| panic!("PRODUCT: status omitted store {name}: {report}"));
            let actual = std::fs::metadata(path).unwrap().len();
            assert_eq!(
                row["file_bytes"].as_u64(),
                Some(actual),
                "PRODUCT: {name} file length differs from the OS: {row}; actual={actual}"
            );
            assert_eq!(
                row["path"].as_str(),
                path.to_str(),
                "PRODUCT: wrong store path: {row}"
            );
            let after = free(path);
            let reported = row["free_bytes"]
                .as_u64()
                .unwrap_or_else(|| panic!("PRODUCT: {name} free bytes unavailable: {row}"));
            let tolerance = 64 * 1024 * 1024;
            assert!(reported > 0 &&
                reported >= before[index].min(after).saturating_sub(tolerance) &&
                reported <= before[index].max(after).saturating_add(tolerance),
                "PRODUCT: {name} free bytes disagree with fresh OS samples: {row}; before={} after={after}", before[index]);
        }
        let plain = run(&["status", "--node", selected], "");
        for (name, path) in &stores {
            assert!(
                plain.contains(name) && plain.contains(path.to_string_lossy().as_ref()),
                "PRODUCT: plain status must name {name}'s store: {plain}"
            );
        }
        assert!(
            plain.contains("free disk") && plain.contains("bytes"),
            "PRODUCT: plain status must show store and free-disk bytes: {plain}"
        );
        eprintln!("OBSERVATION selected={selected}: {out}\n{plain}");
    }
    // A Locked store has no writer. Hide only this proof's file to stage unavailable metadata.
    let missing = &stores[1].1;
    let saved = missing.with_extension("proof-held");
    std::fs::rename(missing, &saved).expect("APPARATUS: hide own Locked store");
    let out = run(&["status", "--node", "small", "--json"], "");
    let plain = run(&["status", "--node", "small"], "");
    std::fs::rename(&saved, missing).expect("APPARATUS: restore own Locked store");
    let report: Value = serde_json::from_str(&out).unwrap();
    let row = report["stores"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["node"] == "large")
        .expect("PRODUCT: missing store omitted");
    assert!(
        row["file_bytes"].is_null() && row["file_error"].as_str().is_some_and(|s| !s.is_empty()),
        "PRODUCT: unreadable store must be unavailable with its reason, never zero: {row}"
    );
    assert!(
        row["free_bytes"].is_null() && row["free_error"].as_str().is_some_and(|s| !s.is_empty()),
        "PRODUCT: unavailable filesystem sample must retain its reason: {row}"
    );
    assert!(
        plain.contains("unavailable") && plain.contains("large"),
        "PRODUCT: plain status hides the unreadable store reason: {plain}"
    );
}
