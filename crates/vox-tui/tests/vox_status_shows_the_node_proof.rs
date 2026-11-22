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

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_stalled_author_is_not_hidden_by_other_members_new_entries);

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

/// A healthy reader must start its deficit observation even if every later look sees a new window.
#[cfg(feature = "test-knobs")]
fn observe_reselection_without_walk(
    w: &World,
    hold: &std::path::Path,
    process: &mut world::VoxProc,
) {
    use vox_core::node::ipc::{Frame, Request};
    let entered = hold.with_extension("entered");
    let window = || {
        std::fs::read_to_string(&entered).ok().and_then(|text| {
            let through = text
                .split_whitespace()
                .find_map(|word| word.strip_prefix("through=")?.parse::<u64>().ok())?;
            let remaining = text
                .split_whitespace()
                .find_map(|word| word.strip_prefix("remaining=")?.parse::<u64>().ok())?;
            Some((through, remaining))
        })
    };
    let head = status_json(&w.host_dir, "reselection author")["rooms"][0]["own_feed_through"]
        .as_u64()
        .expect("APPARATUS: author's initial head");
    let bound = Instant::now() + Duration::from_secs(360);
    while window().is_none_or(|(through, _)| through < head) {
        assert!(
            Instant::now() < bound,
            "APPARATUS: initial live window was not selected"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let healthy = loop {
        let current = status_json(&w.guest_dir, "healthy before reselection");
        let member = current["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == w.host_fp)
            .unwrap();
        let gap = member["missing_live_entries"].as_u64().unwrap_or_else(|| {
            head.saturating_sub(
                member["verified_through"]
                    .as_u64()
                    .or_else(|| member["holds_through"].as_u64())
                    .unwrap_or(0),
            )
        });
        if member["connected"] == true
            && member["advertised_through"].as_u64().unwrap_or(head) >= head
            && gap == 0
            && current["rooms"][0]["not_receiving"] != true
        {
            break current;
        }
        assert!(Instant::now() < bound, "APPARATUS: reader was not healthy with a completed live window before reselection: {current}");
        std::thread::sleep(Duration::from_millis(100));
    };
    receipt_mutant_witness(&healthy, Some(process));
    std::fs::write(hold, format!("{} hold\n", w.host_fp))
        .expect("APPARATUS: hold every author walk");
    let cid = vox_core::node::link::b32_decode(&w.room, "proof room").unwrap();
    let rt = tokio::runtime::Runtime::new().expect("APPARATUS: reselection runtime");
    let mut previous = head;
    let mut started = None;
    let mut round = 0;
    let last_round = loop {
        rt.block_on(async {
            let mut author = local_attach::node_client(&w.host_dir, "default")
                .await
                .expect("APPARATUS: reselection author's socket");
            for number in 0..256 {
                let reply = author
                    .request(&Request::Post {
                        channel_id: cid,
                        text: format!("reselected-{round}-{number:03}"),
                        card: false,
                    })
                    .await;
                assert!(
                    matches!(reply, Ok(Frame::Ok)),
                    "APPARATUS: author could not advance its head: {reply:?}"
                );
            }
        });
        let (through, remaining) = loop {
            if let Some(position) = window()
                .filter(|(through, remaining)| *through >= previous + 128 && *remaining >= 20)
            {
                break position;
            }
            assert!(Instant::now() < bound, "APPARATUS: a newer live window was not selected while its walk was held; previous={previous}, marker={:?}", window());
            std::thread::sleep(Duration::from_millis(50));
        };
        // Notifications are off for this reader: no sampler looks between these reports.
        // Each report follows a real, newer selected window, never a fabricated cursor.
        let current = status_json(&w.guest_dir, "reselected without walking");
        let member = current["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == w.host_fp)
            .unwrap();
        assert!(
            member["connected"] == true
                && member["missing_live_entries"].as_u64().unwrap_or(remaining) >= 20,
            "APPARATUS: the held reselected window has no connected >=20-entry deficit: {current}"
        );
        let now = current["now_ms"].as_u64().unwrap();
        let first = *started.get_or_insert(now);
        let threshold = current["not_receiving_after_ms"].as_u64().unwrap_or(60_000);
        eprintln!("[proof] reselected without a walk: through {previous}->{through}, remaining={remaining}, elapsed={}, member={member}", now.saturating_sub(first));
        if current["rooms"][0]["not_receiving"] == true && now.saturating_sub(first) > threshold {
            break round;
        }
        assert!(now.saturating_sub(first) <= threshold * 2 + 10_000,
            "PRODUCT: a previously healthy member stayed healthy through repeated window re-selection without walking, despite >=20 live entries missing for two receipt thresholds: {current}");
        previous = through;
        round += 1;
    };
    std::fs::remove_file(hold).expect("APPARATUS: release reselecting reader");
    let recovery = Instant::now() + Duration::from_secs(180);
    loop {
        let (ok, read, err) = vox_once(&w.guest_dir, &args(&["room", "read", &w.room, "--json"]));
        assert!(
            ok,
            "APPARATUS: reselection recovery read failed: {read}{err}"
        );
        let current = status_json(&w.guest_dir, "reselection recovered");
        let pending = ["running", "ready", "deferred"].iter().any(|lane| {
            current["lanes"]["bounded"][*lane]
                .as_array()
                .into_iter()
                .flatten()
                .any(|flow| flow["peer"] == w.host_fp && flow["room"] == w.room)
        });
        if (136..256).all(|n| read.contains(&format!("reselected-{last_round}-{n:03}"))) && !pending
        {
            assert!(current["rooms"][0]["not_receiving"] == false,
                "PRODUCT: the reader's live window filled but its not-receiving verdict did not clear: {current}");
            break;
        }
        assert!(Instant::now() < recovery, "APPARATUS: could not recover the reader before the withheld-head observation: {current}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// RG-7: a fresh live-window selection alone must not postpone a stalled receipt alarm.
/// Attach explicitly: this tests receipts, not automatic saved-room recovery (ledger entry 40).
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries and production Argon2id; run in release with test-knobs"]
fn a_reselected_window_does_not_restart_a_stalled_receipt_observation() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_LIVE_WINDOW_FILE"]);
    let sink = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: service port");
    let port = sink.local_addr().expect("APPARATUS: bound service").port();
    let mut w = World::new(port, true);
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    let (ok, out, err) = vox_once(
        &w.guest_dir,
        &args(&["trust", "add", &w.host_fp, "--name", "author"]),
    );
    assert!(ok, "APPARATUS: trusting author failed: {out}{err}");
    let run = |dir: &std::path::Path, argv: &[&str]| {
        let (ok, out, err) = vox_once(dir, &args(argv));
        assert!(ok, "APPARATUS: staging vox {argv:?} failed: {out}{err}");
        out
    };
    drop(w.host.take());
    world::reap_daemon(&w.host_dir);
    let pass = w.tmp.path().join("daemon-passphrases");
    std::fs::write(&pass, format!("{}\n{}\n", world::IDENTITY, w.passphrase))
        .expect("APPARATUS: scratch passphrase file");
    let mut author = world::VoxProc::spawn_env(
        "reselection-author",
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
        &[],
    );
    author.expect_line("author's room open", |line| {
        line.starts_with("vox daemon: holding room") && line.contains(&w.room)
    });
    let hold = w.tmp.path().join("reselect-without-walking");
    std::fs::write(&hold, format!("{} pause-ms=0\n", w.host_fp))
        .expect("APPARATUS: live-window witness");
    let paths = vox_core::node::paths::Paths::resolve(
        "default",
        Some(&w.guest_dir),
        Some(&w.guest_dir.join("cfg")),
    )
    .expect("APPARATUS: reader settings");
    let config = paths
        .own_config_path("config")
        .expect("APPARATUS: reader config");
    let mut settings = std::fs::read_to_string(&config).unwrap_or_default();
    settings.push_str("\nnotify = off\n");
    std::fs::write(config, settings).expect("APPARATUS: disable the reader's sampling watcher");
    world::reap_daemon(&w.guest_dir);
    let mut reader = world::VoxProc::spawn_env(
        "withheld-reader",
        &w.guest_dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            &world::utf8(&pass),
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[("VOX_TEST_HOLD_LIVE_WINDOW_FILE", &world::utf8(&hold))],
    );
    reader.expect_line("reader's control socket", |line| {
        line.starts_with("vox daemon: control socket ")
    });
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    run(
        &w.host_dir,
        &["room", "post", &w.room, "received-before-reselection"],
    );
    loop {
        let read = run(&w.guest_dir, &["room", "read", &w.room, "--json"]);
        if read.contains("received-before-reselection") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    observe_reselection_without_walk(&w, &hold, &mut reader);
    drop(author);
}

/// RG-7: a fresh receipt clock cannot advance during exchanges that serve no new entries.
/// Fully receive both initial feeds, stop both daemons through their control protocol, enable
/// head refusal, and restart the reader while its sole room peer is still stopped. The provider
/// only responds, so new hints arrive in fetched inventories, never unsolicited announcements.
/// Thus no previously admitted flow or commit can land after the clock observation starts.
/// Attach explicitly: this tests receipts, not automatic saved-room recovery (ledger entry 40).
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries and production Argon2id; run in release with test-knobs"]
fn status_names_a_connected_member_whose_posts_are_not_received() {
    use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest};
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_UNAVAILABLE_HEAD_FILE", "VOX_TEST_RESPOND_ONLY"]);
    let sink = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: service port");
    let mut w = World::new(
        sink.local_addr()
            .expect("APPARATUS: service address")
            .port(),
        true,
    );
    let run = |data: &std::path::Path, argv: &[&str]| {
        let (ok, out, err) = vox_once(data, &args(argv));
        assert!(ok, "APPARATUS: vox {argv:?} failed: {out}{err}");
        out
    };
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    run(
        &w.guest_dir,
        &["trust", "add", &w.host_fp, "--name", "author"],
    );
    run(
        &w.host_dir,
        &["room", "post", &w.room, "clock-before-restart"],
    );
    let full = Instant::now() + Duration::from_secs(120);
    loop {
        let read = run(&w.guest_dir, &["room", "read", &w.room, "--json"]);
        let host = status_json(&w.host_dir, "clock author fully received");
        let guest = status_json(&w.guest_dir, "clock reader fully received");
        let coverage = |v: &Value, peer: &str| {
            v["rooms"][0]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["id"] == peer)
                .map(|m| {
                    (
                        m["connected"] == true,
                        m["verified_through"].as_u64().unwrap_or(0),
                    )
                })
                .unwrap_or((false, 0))
        };
        let host_head = host["rooms"][0]["own_feed_through"].as_u64().unwrap();
        let guest_head = guest["rooms"][0]["own_feed_through"].as_u64().unwrap();
        let (host_connected, host_holds) = coverage(&host, &w.guest_fp);
        let (guest_connected, guest_holds) = coverage(&guest, &w.host_fp);
        if read.contains("clock-before-restart")
            && host_connected
            && guest_connected
            && host_holds >= guest_head
            && guest_holds >= host_head
        {
            eprintln!("[proof] fully received before retirement: author head={host_head}, reader holds={guest_holds}; reader head={guest_head}, author holds={host_holds}");
            break;
        }
        assert!(Instant::now() < full, "APPARATUS: the two initial feeds were not fully received before restart: {host}\n{guest}");
        std::thread::sleep(Duration::from_millis(100));
    }
    for data in [&w.host_dir, &w.guest_dir] {
        let paths =
            vox_core::node::paths::Paths::resolve("default", Some(data), Some(&data.join("cfg")))
                .unwrap();
        let config = paths.own_config_path("config").unwrap();
        let mut settings = std::fs::read_to_string(&config).unwrap_or_default();
        settings.push_str("\nnotify = off\n");
        std::fs::write(config, settings).expect("APPARATUS: disable scratch notification sampler");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let stop = |data: &std::path::Path| {
        let account =
            vox_core::node::paths::Account::of(Some(data), Some(&data.join("cfg"))).unwrap();
        let lock =
            std::fs::File::open(data.join(".daemon/lock")).expect("APPARATUS: owned daemon lock");
        let answer = runtime.block_on(async {
            let mut client = DaemonClient::open(&account.socket())
                .await
                .expect("APPARATUS: open owned daemon control");
            client
                .request(DaemonRequest::Stop)
                .await
                .expect("APPARATUS: clean stop request")
        });
        assert!(
            matches!(answer, DaemonFrame::Ok),
            "APPARATUS: owned daemon refused clean stop: {answer:?}"
        );
        let bound = Instant::now() + Duration::from_secs(45);
        loop {
            match lock.try_lock() {
                Ok(()) => {
                    lock.unlock().unwrap();
                    break;
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(error) => panic!("APPARATUS: cannot observe completed clean shutdown: {error}"),
            }
            assert!(
                Instant::now() < bound,
                "APPARATUS: owned daemon did not finish clean shutdown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    stop(&w.guest_dir);
    stop(&w.host_dir);
    drop(w.host.take());
    let pass = w.tmp.path().join("clock-daemon-passphrases");
    std::fs::write(&pass, format!("{}\n{}\n", world::IDENTITY, w.passphrase))
        .expect("APPARATUS: scratch passphrases");
    let marker = w.tmp.path().join("clock-head-refusal");
    std::fs::write(&marker, format!("{} {}\n", w.host_fp, w.guest_fp))
        .expect("APPARATUS: refusal before either restart");
    let spawn = |name: &str, data: &std::path::Path, anchor: &str, env: &[(&str, &str)]| {
        world::VoxProc::spawn_env(
            name,
            data,
            &args(&[
                "daemon",
                "--passphrase-file",
                &world::utf8(&pass),
                "--anchor",
                anchor,
                "--listen",
                "127.0.0.1:0",
            ]),
            env,
        )
    };
    let mut reader = spawn("clock-reader", &w.guest_dir, &w.guest_anchor, &[]);
    reader.expect_line("fresh reader control socket", |line| {
        line.starts_with("vox daemon: control socket ")
    });
    local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
    let before = status_json(&w.guest_dir, "fresh clock before the only provider starts");
    let peers = before["rooms"][0]["members"].as_array().unwrap();
    assert!(
        peers.len() == 2
            && peers
                .iter()
                .all(|m| m["me"] == true || m["connected"] == false),
        "APPARATUS: the fresh reader has another source of room entries: {before}"
    );
    receipt_mutant_witness(&before, Some(&mut reader));
    assert!(
        before["rooms"][0]["last_sync_ms"].is_null(),
        "PRODUCT: a fresh reader reported a receipt before its only provider was running: {before}"
    );
    let fetched = |v: &Value| -> u64 {
        v["sync"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["peer"] == w.host_fp)
            .filter_map(|row| row["fetched_completed"].as_u64())
            .sum()
    };
    let cycles = fetched(&before);
    let mut author = spawn(
        "clock-refusing-author",
        &w.host_dir,
        &w.host_anchor,
        &[
            ("VOX_TEST_UNAVAILABLE_HEAD_FILE", &world::utf8(&marker)),
            ("VOX_TEST_RESPOND_ONLY", "1"),
        ],
    );
    author.expect_line("refusing author control socket", |line| {
        line.starts_with("vox daemon: control socket ")
    });
    local_attach::Root::at(&w.host_dir, world::IDENTITY).attach("default");
    for number in 1..=20 {
        run(
            &w.host_dir,
            &[
                "room",
                "post",
                &w.room,
                &format!("withheld-post-{number:02}"),
            ],
        );
    }
    let start = status_json(&w.guest_dir, "withheld clock observation")["now_ms"]
        .as_u64()
        .unwrap();
    let bound = Instant::now() + Duration::from_secs(180);
    let after = loop {
        let current = status_json(&w.guest_dir, "empty fetched rounds");
        let text = status_text(&w.guest_dir, "empty fetched rounds");
        if fetched(&current) >= cycles + 3 && text.contains("not receiving") {
            break current;
        }
        let elapsed = current["now_ms"].as_u64().unwrap().saturating_sub(start);
        let threshold = current["not_receiving_after_ms"].as_u64().unwrap_or(60_000);
        assert!(elapsed <= threshold * 2 + 10_000,
            "PRODUCT: connected author's withheld entries did not raise not receiving within two product thresholds: {current}");
        assert!(
            Instant::now() < bound,
            "APPARATUS: product clock did not advance to the observation bound: {current}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let read = run(&w.guest_dir, &["room", "read", &w.room, "--json"]);
    assert!(
        !read.contains("withheld-post-"),
        "APPARATUS: refusal did not withhold the new posts: {read}"
    );
    receipt_mutant_witness(&after, Some(&mut reader));
    reader.expect_line("new hint offered without receiving its entries", |line| {
        line.contains("RG7_HINT_OFFERED ")
    });
    if let Some(line) = reader
        .transcript()
        .lines()
        .find(|line| line.contains("RG7_HINT_OFFERED "))
    {
        eprintln!("[proof] daemon hint witness: {line}");
    }
    eprintln!(
        "[proof] fresh clock after three refused fetched rounds: before={} after={}\n{after}",
        before["rooms"][0]["last_sync_ms"], after["rooms"][0]["last_sync_ms"]
    );
    assert_eq!(after["rooms"][0]["last_sync_ms"], before["rooms"][0]["last_sync_ms"],
        "PRODUCT: fresh receipt clock advanced although its only provider refused all unseen heads and every earlier flow was retired: {after}");
    let text = status_text(&w.guest_dir, "withheld reader");
    assert!(
        text.contains("live entries have not been held for over 60s")
            && !text.contains("no live-window receipt progress observed"),
        "PRODUCT: status overstates what its receipt samples prove: {text}"
    );
    for member in after["rooms"][0]["members"].as_array().unwrap() {
        let id = member["id"].as_str().unwrap();
        if member["me"] == true {
            assert!(
                member["holds_through"].is_null(),
                "PRODUCT: setup headers were reported as shown messages: {text}"
            );
        }
        assert!(
            text.lines().any(|line| line.contains(&id[..12])
                && line.contains("latest shown message at feed entry")),
            "PRODUCT: status does not name received message coverage: {text}"
        );
    }
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
    let completions = |v: &Value| -> u64 {
        v["sync"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|lane| lane["peer"] == w.host_fp)
            .filter_map(|lane| lane["fetched_completed"].as_u64())
            .sum()
    };
    let before = completions(&status_json(&w.guest_dir, "reader"));
    loop {
        if completions(&status_json(&w.guest_dir, "reader")) >= before + 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
            assert!(member["holds_through"].is_null(),
                "PRODUCT: read-only member authored no messages, but status calls its receipt feed a shown message: {member}");
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

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binaries and a newcomer filling a sparse live window; run in release"]
fn a_newcomer_receiving_its_live_window_does_not_raise_a_missing_history_alarm() {
    sparse_live_window_reads_healthy(WindowScene::Receiving);
}

#[cfg(all(feature = "test-knobs", feature = "optional-proofs"))]
#[test]
#[ignore = "optional: three real members, a held author and minute-spaced other posts"]
fn a_stalled_author_is_not_hidden_by_other_members_new_entries() {
    sparse_live_window_reads_healthy(WindowScene::Stalled);
}

enum WindowScene {
    Newcomer,
    Offline,
    #[cfg(feature = "test-knobs")]
    Receiving,
    #[cfg(all(feature = "test-knobs", feature = "optional-proofs"))]
    Stalled,
}

/// The archive is deliberately never requested. The verdict is the reader's real status,
/// after it shows every post in the newest 128 feed positions and completes three more
/// room exchanges. The catch-up case also observes a partial read before letting it finish.
fn sparse_live_window_reads_healthy(scene: WindowScene) {
    let offline = matches!(scene, WindowScene::Offline);
    #[cfg(feature = "test-knobs")]
    let catching_up = matches!(scene, WindowScene::Receiving);
    #[cfg(not(feature = "test-knobs"))]
    let catching_up = false;
    #[cfg(all(feature = "test-knobs", feature = "optional-proofs"))]
    let stalled = matches!(scene, WindowScene::Stalled);
    #[cfg(not(all(feature = "test-knobs", feature = "optional-proofs")))]
    let stalled = false;
    let staged = catching_up || stalled;
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
    if stalled {
        local_attach::Root::at(&w.guest_dir, world::IDENTITY).attach("default");
        for (dir, peer) in [(&reader, &w.guest_fp), (&w.guest_dir, &reader_id)] {
            let (ok, out, err) = vox_once(
                dir,
                &args(&["trust", "add", peer, "--name", "other-reader"]),
            );
            assert!(ok, "APPARATUS: third-member trust: {out}{err}");
        }
        // Receive the third member's key and a real post before parking the author.
        // Otherwise its key dependency can sit behind the deliberately held author walk.
        let (ok, _, out, err) = w.join(&reader);
        assert!(ok, "APPARATUS: third reader joined: {out}{err}");
        let (ok, out, err) = vox_once(
            &w.guest_dir,
            &args(&["room", "post", &w.room, "third-member-ready"]),
        );
        assert!(ok, "APPARATUS: third member ready post: {out}{err}");
        loop {
            let (ok, read, err) = vox_once(&reader, &args(&["room", "read", &w.room, "--json"]));
            if !ok && err.contains("room is refreshing saved history; retry") {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            assert!(ok, "APPARATUS: third reader ready read: {read}{err}");
            if read.contains("third-member-ready") {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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
    let hold = w.tmp.path().join("hold-live-window");
    let entered = hold.with_extension("entered");
    let notices = w.tmp.path().join("reader-notices");
    let script = w.tmp.path().join("reader-notify");
    if staged {
        use std::os::unix::fs::PermissionsExt;
        let selector = if catching_up {
            format!("{} pause-ms=700\n", w.host_fp)
        } else {
            format!("{} 96\n", w.host_fp)
        };
        std::fs::write(&hold, selector).expect("APPARATUS: live-window staging");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s|%s\\n' \"$1\" \"$2\" >> '{}'\n",
                notices.display()
            ),
        )
        .expect("APPARATUS: notification recorder");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("APPARATUS: executable notification recorder");
    }
    let mut restarted = None;
    if offline || staged {
        let pass = w.tmp.path().join("offline-reader-passphrases");
        std::fs::write(&pass, format!("{}\n{}\n", world::IDENTITY, w.passphrase))
            .expect("APPARATUS: reader passphrases");
        let hold_path = world::utf8(&hold);
        let notify_path = world::utf8(&script);
        let env = if staged {
            vec![
                ("VOX_TEST_HOLD_LIVE_WINDOW_FILE", hold_path.as_str()),
                ("VOX_NOTIFY_COMMAND", notify_path.as_str()),
            ]
        } else {
            Vec::new()
        };
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
            &env,
        );
        process.expect_line("reader daemon ready", |line| {
            if offline || stalled {
                line.contains("holding room") && line.contains(&w.room)
            } else {
                line.starts_with("vox daemon: control socket")
            }
        });
        restarted = Some(process);
    }
    if !offline && !stalled {
        let (ok, _, out, err) = w.join(&reader);
        assert!(ok, "APPARATUS: newcomer did not join: {out}{err}");
    }
    local_attach::Root::at(&reader, world::IDENTITY).attach("default");
    let mut catchup_start = None;
    let mut first_shown = 0;
    if staged {
        while !entered.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        if stalled {
            let first = status_json(&reader, "held newcomer");
            receipt_mutant_witness(&first, restarted.as_mut());
            let started = first["now_ms"]
                .as_u64()
                .expect("APPARATUS: held status clock");
            let mut next_post = started;
            let mut posts = 0;
            let mut last_received = first["rooms"][0]["last_sync_ms"].as_u64().unwrap_or(0);
            let bound = Instant::now() + Duration::from_secs(180);
            loop {
                let snapshot = status_json(&reader, "held newcomer");
                let now = snapshot["now_ms"].as_u64().unwrap();
                if now >= next_post {
                    let word = format!("other-member-still-posting-{posts}");
                    let (ok, out, err) =
                        vox_once(&w.guest_dir, &args(&["room", "post", &w.room, &word]));
                    assert!(ok, "APPARATUS: third member's post: {out}{err}");
                    loop {
                        let (ok, read, err) =
                            vox_once(&reader, &args(&["room", "read", &w.room, "--json"]));
                        assert!(ok, "PRODUCT: held reader's read failed: {read}{err}");
                        if read.contains(&word) {
                            break;
                        }
                        if Instant::now() >= bound {
                            panic!("APPARATUS: third-member traffic never reached the held reader; reader status {}; third-member status {}; author status {}; read: {read}",
                                status_json(&reader, "held reader diagnostic"),
                                status_json(&w.guest_dir, "third-member diagnostic"),
                                status_json(&w.host_dir, "author diagnostic"));
                        }
                        std::thread::sleep(Duration::from_millis(250));
                    }
                    posts += 1;
                    next_post = started + posts * 60_000;
                }
                let snapshot = status_json(&reader, "held author observation");
                let member = snapshot["rooms"][0]["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|member| member["id"] == w.host_fp)
                    .expect("APPARATUS: held author");
                let (ok, read, err) =
                    vox_once(&reader, &args(&["room", "read", &w.room, "--json"]));
                assert!(ok, "PRODUCT: held room read failed: {read}{err}");
                let shown = (52..180)
                    .filter(|n| read.contains(&format!("live-window-post-{n:03}")))
                    .count();
                assert!(member["connected"] == true && (1..=108).contains(&shown),
                    "APPARATUS: author is not connected with >=20 live posts still absent: shown={shown}; {member}");
                let received = snapshot["rooms"][0]["last_sync_ms"].as_u64().unwrap_or(0);
                last_received = last_received.max(received);
                let text = status_text(&reader, "held author");
                // Observe the room clock after the newest other-member post, not just the
                // previous one: an any-entry reset mutant must have had its reset edge.
                if text.contains("not receiving")
                    && text.contains(&w.host_fp[..12])
                    && posts >= 2
                    && last_received >= started + (posts - 1) * 60_000
                {
                    eprintln!("[proof] held author, {posts} other-member posts received, room last sync {last_received} > {started}:\n{text}\n{snapshot}");
                    return;
                }
                let elapsed = snapshot["now_ms"].as_u64().unwrap().saturating_sub(started);
                let threshold = snapshot["not_receiving_after_ms"]
                    .as_u64()
                    .unwrap_or(60_000);
                assert!(elapsed <= threshold * 2 + 10_000,
                    "PRODUCT: held author's >=20-entry live deficit stayed healthy while other members posted; elapsed={elapsed}, threshold={threshold}, posts={posts}, member={member}, status:\n{text}\n{snapshot}");
                assert!(
                    Instant::now() < bound,
                    "APPARATUS: product clock failed to reach two thresholds: {snapshot}"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        let mut start = status_json(&reader, "receiving newcomer");
        loop {
            let (ok, read, err) = vox_once(&reader, &args(&["room", "read", &w.room, "--json"]));
            assert!(ok, "PRODUCT: receiving read failed: {read}{err}");
            first_shown = (52..180)
                .filter(|n| read.contains(&format!("live-window-post-{n:03}")))
                .count();
            if first_shown > 0 && first_shown <= 108 {
                break;
            }
            start = status_json(&reader, "receiving newcomer");
            std::thread::sleep(Duration::from_millis(100));
        }
        catchup_start = start["now_ms"].as_u64();
        receipt_mutant_witness(&start, restarted.as_mut());
        eprintln!("[proof] catch-up starts with {first_shown}/128 newest posts visible; {start}");
    }
    let completed = |snapshot: &Value| -> u64 {
        snapshot["sync"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|lane| lane["peer"] == w.host_fp)
            .filter_map(|lane| lane["completed"].as_u64())
            .sum()
    };
    let mut after_shown = None;
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
        let first_post = 52 + advertised.saturating_sub(head) as usize;
        let shown =
            (first_post..180).all(|number| read.contains(&format!("live-window-post-{number:03}")));
        if catching_up {
            let text = status_text(&reader, "progressing newcomer");
            let notes = std::fs::read_to_string(&notices).unwrap_or_default();
            assert!(
                !text.contains("not receiving") && !notes.contains("not receiving"),
                "PRODUCT: progressing newcomer raised a missing-history alarm:\n{text}\n{notes}"
            );
        }
        if shown {
            assert!(
                !read.contains("live-window-post-000"),
                "APPARATUS: the on-demand archive was fetched without being requested: {read}"
            );
            let cycles = *after_shown.get_or_insert_with(|| completed(&snapshot));
            let member = snapshot["rooms"][0]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|member| member["id"] == w.host_fp)
                .expect("APPARATUS: author member");
            if member["connected"] == true && completed(&snapshot) >= cycles + 3 {
                if let Some(started) = catchup_start {
                    let elapsed = snapshot["now_ms"].as_u64().unwrap().saturating_sub(started);
                    let threshold = snapshot["not_receiving_after_ms"]
                        .as_u64()
                        .unwrap_or(60_000);
                    assert!(elapsed > threshold && first_shown < 108,
                        "APPARATUS: progressing catch-up did not span the product's receipt threshold: elapsed={elapsed}, threshold={threshold}, first_shown={first_shown}; {snapshot}");
                    eprintln!("[proof] catch-up progressed beyond product threshold: elapsed={elapsed}, threshold={threshold}; no missing-history notice");
                }
                break snapshot;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
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
    if !catching_up {
        receipt_mutant_witness(&snapshot, restarted.as_mut());
        receipt_observation(&reader, "fully received live window");
    }
    let text = status_text(&reader, "sparse reader");
    eprintln!("[proof] offline={offline}, author's feed head={head}, newest live-window posts shown, archive absent:\n{text}\n{snapshot}");
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
