//! V030-45 (#419, ADR-012 N-58, "Real router, opt-in heavy proof") — **against the operator's own
//! router: a mapping granted on the rung `vox status` names, renewed under its nonce, and deleted
//! at stop**, through the shipped binary.
//!
//! **Opt-in, the operator runs it.** It talks to the machine's real default gateway, so it does
//! nothing unless `VOX_PROOF_REAL_ROUTER` is set:
//! - unset: prints `HEAVY PROOF NOT RUN` and passes;
//! - `dry`: finds the gateway, this machine's address towards it and the port it would map, says
//!   exactly what it would send, and **stops before any packet reaches the router** (no daemon is
//!   started: a daemon asks its gateway at once);
//! - `1`: the live run below.
//!
//! **No sudo.** PCP and NAT-PMP are plain UDP to the router's port 5351 from an ephemeral port; the
//! daemon listens on an unprivileged port this proof picks. The proof refuses to run as root
//! (a daemon refuses control connections from uid 0 anyway).
//!
//! **The live run**, with a `vox daemon` on `0.0.0.0:<P>` asking for a short lifetime
//! (`VOX_TEST_MAP_LIFETIME_SECS=60`, test-knobs) and no gateway override, so it asks what it asks
//! in real use:
//! 1. **granted on the named rung:** `vox status --json` names the gateway that answered and its
//!    rung, with the external address and lifetime granted. A router that maps nothing for this
//!    machine is `CANNOT MEASURE`, naming what was asked. The rest needs PCP; a router that
//!    answered on NAT-PMP or UPnP-IGD only is `CANNOT MEASURE` for it, saying so.
//! 2. **the mapping is the daemon's, under its nonce:** this proof sends its own PCP MAP for the
//!    same internal port with a fresh nonce; the router must refuse it `NOT_AUTHORIZED` (RFC 6887
//!    §11.3), which also shows the router enforces nonces, so the next step means something;
//! 3. **renewed under its nonce:** `vox status` shows a renewal (`renewal: true`) answered by that
//!    server on PCP, no sooner than 1/2 and no later than 5/8 of the granted lifetime (plus
//!    slack), and the proof's fresh-nonce MAP is still refused;
//! 4. **deleted at stop:** after SIGTERM to the daemon (by its pid) and its exit, the proof's
//!    fresh-nonce MAP for the same port **succeeds**: no mapping under another nonce is left.
//!
//! **Cleanup on every exit**, by a guard that runs on success and on every red: the daemon, if
//! still running, gets SIGTERM (its own stop deletes its mappings) and is waited for, then killed
//! by pid; every MAP this proof sent that the router may have granted is deleted with its nonce
//! (lifetime 0). Only the watchdog's SIGKILL skips it; the mapping then expires in at most the
//! lifetime granted.
//!
//! **Which side a red is on.** The daemon's mapping missing, a renewal refused or unanswered, or a
//! mapping left at stop is `PRODUCT:`. The router not speaking PCP, not enforcing nonces, or
//! granting a lifetime too long to see a renewal within the watchdog's budget is `CANNOT MEASURE`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;
use world::{args, tempdir, utf8, vox_once, Reaper, VoxProc, IDENTITY};

/// The gate.
const GATE: &str = "VOX_PROOF_REAL_ROUTER";
/// The lifetime the daemon asks for (the router may grant another).
const ASK_LIFETIME: u32 = 60;
/// The lifetime of this proof's own probe MAPs.
const PROBE_LIFETIME: u32 = 60;
/// How long the first discovery may take (PCP, NAT-PMP and UPnP's search, with room).
const DISCOVERY: Duration = Duration::from_secs(45);
/// The longest this proof waits for a renewal: inside the watchdog's 600 s.
const RENEWAL_CAP: Duration = Duration::from_secs(420);
/// PCP's result code for a request under another nonce (RFC 6887 §7.4).
const NOT_AUTHORIZED: u8 = 2;

/// The machine's IPv4 default gateway, as the operating system says it.
fn default_gateway() -> Ipv4Addr {
    let (cmd, args_): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("/sbin/route", &["-n", "get", "default"])
    } else {
        ("ip", &["-4", "route", "show", "default"])
    };
    let out = std::process::Command::new(cmd)
        .args(args_)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run {cmd}: {e}"));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let found = if cfg!(target_os = "macos") {
        text.lines()
            .find_map(|l| l.trim().strip_prefix("gateway:").map(str::trim))
            .map(str::to_owned)
    } else {
        text.split_whitespace()
            .skip_while(|w| *w != "via")
            .nth(1)
            .map(str::to_owned)
    };
    found
        .and_then(|g| g.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE (precondition unmet): this machine has no IPv4 default gateway:\n{text}"
            )
        })
}

/// This machine's address towards `server`: a connected UDP socket's source, no packet sent.
fn local_towards(server: SocketAddr) -> Ipv4Addr {
    let s = UdpSocket::bind("0.0.0.0:0").expect("APPARATUS: a UDP socket");
    s.connect(server)
        .expect("APPARATUS: connect towards the gateway");
    match s.local_addr().expect("APPARATUS: its local address") {
        SocketAddr::V4(a) => *a.ip(),
        SocketAddr::V6(_) => panic!("APPARATUS: an IPv6 source towards {server}"),
    }
}

/// A free UDP port above 1024, for the daemon to listen on.
fn free_port() -> u16 {
    let s = UdpSocket::bind("0.0.0.0:0").expect("APPARATUS: a UDP socket");
    s.local_addr().expect("APPARATUS: its port").port()
}

/// A fresh random PCP nonce.
fn nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    let mut f = std::fs::File::open("/dev/urandom").expect("APPARATUS: /dev/urandom");
    std::io::Read::read_exact(&mut f, &mut n).expect("APPARATUS: reading /dev/urandom");
    n
}

/// One PCP MAP (RFC 6887 §11.1) for UDP `port` from this machine to `server`, retransmitted at
/// 0, 0.25, 0.75 and 1.75 s; the result code and the lifetime of the answer that echoes `nonce`.
fn pcp_map(server: SocketAddr, nonce: [u8; 12], port: u16, lifetime: u32) -> Option<(u8, u32)> {
    let s = UdpSocket::bind("0.0.0.0:0").expect("APPARATUS: a UDP socket");
    s.connect(server).expect("APPARATUS: connect to the router");
    let client = match s.local_addr().expect("APPARATUS: local address") {
        SocketAddr::V4(a) => *a.ip(),
        SocketAddr::V6(_) => return None,
    };
    let mut req = [0u8; 60];
    req[0] = 2;
    req[1] = 1;
    req[4..8].copy_from_slice(&lifetime.to_be_bytes());
    req[8..24].copy_from_slice(&client.to_ipv6_mapped().octets());
    req[24..36].copy_from_slice(&nonce);
    req[36] = 17;
    req[40..42].copy_from_slice(&port.to_be_bytes());
    let mut buf = [0u8; 1100];
    for wait in [250u64, 500, 1000, 2000] {
        let _ = s.send(&req);
        let until = Instant::now() + Duration::from_millis(wait);
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            let _ = s.set_read_timeout(Some(left.max(Duration::from_millis(1))));
            let Ok(n) = s.recv(&mut buf) else { break };
            let r = &buf[..n];
            if n == 60 && r[0] == 2 && r[1] == 0x81 && r[24..36] == nonce {
                return Some((r[3], u32::from_be_bytes([r[4], r[5], r[6], r[7]])));
            }
        }
    }
    None
}

/// What must be undone however the proof ends.
struct Cleanup {
    daemon: Option<VoxProc>,
    server: Option<SocketAddr>,
    port: u16,
    /// Nonces of this proof's own MAPs that the router may have granted.
    probes: Vec<[u8; 12]>,
}

impl Cleanup {
    /// SIGTERM the daemon by its pid and wait for it; how it ended and when the signal went.
    fn stop_daemon(&mut self) -> Option<(Instant, Option<std::process::ExitStatus>)> {
        let mut d = self.daemon.take()?;
        let pid = d.child.id();
        let at = Instant::now();
        let _ = std::process::Command::new("/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let mut exited = None;
        while at.elapsed() < Duration::from_secs(15) {
            if let Ok(Some(s)) = d.child.try_wait() {
                exited = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Dropping it kills by pid what did not exit.
        drop(d);
        Some((at, exited))
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some((_, exited)) = self.stop_daemon() {
            eprintln!("[cleanup] the daemon was stopped: {exited:?}");
        }
        if let Some(server) = self.server {
            for n in self.probes.drain(..) {
                let said = pcp_map(server, n, self.port, 0);
                eprintln!("[cleanup] deleted this proof's MAP {n:02x?} at {server}: {said:?}");
            }
        }
    }
}

/// `vox status --json` of the node on `data`, parsed.
fn status(data: &Path) -> Value {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: `vox status --json` did not answer: {out}\n{err}"
    );
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}):\n{out}"))
}

fn not_root() {
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    assert_ne!(
        uid, "0",
        "APPARATUS: run this as yourself, not root: it needs no privilege, and a daemon refuses \
         control connections from uid 0"
    );
}

#[test]
#[ignore = "opt-in heavy: talks to the machine's real router; the operator runs it"]
fn a_real_router_maps_renews_and_deletes() {
    watchdog::arm();
    let mode = std::env::var(GATE).unwrap_or_default();
    if mode != "1" && mode != "dry" {
        eprintln!(
            "HEAVY PROOF NOT RUN: a_real_router_maps_renews_and_deletes talks to this machine's \
             router. {GATE}=dry shows what it would send and stops before the router; {GATE}=1 \
             runs it."
        );
        return;
    }
    not_root();
    test_knobs::require(&["VOX_TEST_MAP_LIFETIME_SECS"]);
    let gw = default_gateway();
    let gw_server = SocketAddr::new(gw.into(), 5351);
    let local = local_towards(gw_server);
    let port = free_port();
    println!("[proof] default gateway {gw}; this machine is {local} towards it; the daemon will listen on 0.0.0.0:{port}");
    println!(
        "[proof] the live run starts `vox daemon --listen 0.0.0.0:{port}` with \
         VOX_TEST_MAP_LIFETIME_SECS={ASK_LIFETIME} (it asks {gw}:5351, the .1 address, 192.0.0.9 and UPnP as in \
         real use), then sends its own PCP MAPs for UDP {port} from {local} to the server that \
         answers, each with a fresh nonce and lifetime {PROBE_LIFETIME}, and deletes them after. \
         No privilege: ephemeral UDP ports to the router's 5351, and port {port} > 1024."
    );
    if mode == "dry" {
        println!("[proof] DRY RUN: stopping before any packet reaches the router; nothing was sent, no daemon was started.");
        return;
    }

    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    world::mkdir(&data.join("cfg"));
    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");
    let pass = data.join("daemon-passphrase");
    std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: the passphrase file");
    let mut cleanup = Cleanup {
        daemon: None,
        server: None,
        port,
        probes: Vec::new(),
    };
    let mut d = VoxProc::spawn_env(
        "daemon",
        &data,
        &args(&[
            "daemon",
            "--passphrase-file",
            &utf8(&pass),
            "--listen",
            &format!("0.0.0.0:{port}"),
        ]),
        &[("VOX_TEST_MAP_LIFETIME_SECS", &ASK_LIFETIME.to_string())],
    );
    d.expect_line("the daemon to start", |l| l.contains("control socket"));
    cleanup.daemon = Some(d);

    // ---- 1. granted, on the rung status names ----
    let started = Instant::now();
    let first = loop {
        let v = status(&data);
        let g = v["gateway"]["ipv4"].clone();
        if !g["answered"].is_null() {
            break g;
        }
        if started.elapsed() > DISCOVERY {
            panic!(
                "CANNOT MEASURE (precondition unmet): {}s after the daemon started, no gateway \
                 granted a mapping; vox status says it asked {} and none answered. The router \
                 at {gw} does not map for this machine (PCP, NAT-PMP and UPnP-IGD off?).",
                DISCOVERY.as_secs(),
                g["asked"]
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let granted_at = Instant::now();
    let rung = first["answered"]["rung"].as_str().unwrap_or("?").to_owned();
    let server_text = first["answered"]["address"]
        .as_str()
        .unwrap_or("?")
        .to_owned();
    let lifetime = first["answered"]["lifetime"].as_u64().unwrap_or(0);
    println!(
        "[proof] granted: rung {rung} at {server_text}, external {}, lifetime {lifetime}s (asked {}s); vox status asked {}",
        first["answered"]["external"], ASK_LIFETIME, first["asked"]
    );
    assert!(
        ["PCP", "NAT-PMP", "UPnP-IGD"].contains(&rung.as_str()) && lifetime > 0,
        "PRODUCT: vox status names a grant without a rung or a lifetime: {first}"
    );
    assert!(
        rung == "PCP",
        "CANNOT MEASURE (precondition unmet): the router granted on {rung} at {server_text}, which \
         `vox status` names (claim 1 holds); the nonce and deletion claims need PCP, which this \
         router did not answer."
    );
    let server: SocketAddr = server_text
        .parse()
        .unwrap_or_else(|e| panic!("PRODUCT: vox names the PCP server {server_text:?}: {e}"));
    cleanup.server = Some(server);

    // ---- 2. the mapping is the daemon's, under its nonce ----
    let probe = nonce();
    cleanup.probes.push(probe);
    let said = pcp_map(server, probe, port, PROBE_LIFETIME);
    println!("[proof] a fresh-nonce MAP for UDP {port} while the daemon holds it: {said:?}");
    match said {
        Some((NOT_AUTHORIZED, _)) => {}
        Some((0, _)) => panic!(
            "CANNOT MEASURE (precondition unmet): the router at {server} granted a MAP for UDP \
             {port} under a fresh nonce while the daemon held it: it does not enforce RFC 6887 \
             §11.3, so neither the nonce nor the deletion can be shown against it (this MAP is \
             deleted on the way out)."
        ),
        Some((code, _)) => panic!(
            "CANNOT MEASURE: the router at {server} answered a fresh-nonce MAP with result {code}, \
             neither SUCCESS nor NOT_AUTHORIZED"
        ),
        None => panic!(
            "CANNOT MEASURE: the router at {server} did not answer this proof's MAP, though it \
             granted the daemon's"
        ),
    }

    // ---- 3. renewed under its nonce ----
    let window = Duration::from_secs(lifetime * 5 / 8 + 15);
    assert!(
        window <= RENEWAL_CAP,
        "CANNOT MEASURE (precondition unmet): the router granted {lifetime}s for a {ASK_LIFETIME}s \
         request; the first renewal would come after {}s, past what the watchdog allows.",
        lifetime / 2
    );
    let renewed = loop {
        let g = status(&data)["gateway"]["ipv4"].clone();
        if g["renewal"] == serde_json::json!(true) {
            break g;
        }
        assert!(
            granted_at.elapsed() < window,
            "PRODUCT: no renewal of the {lifetime}s mapping at {server} within {}s (RFC 6887 \
             §11.2.1: 1/2-5/8 of the lifetime): vox status says {g}",
            window.as_secs()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let after = granted_at.elapsed().as_secs_f64();
    println!("[proof] renewal seen {after:.1}s after the grant: {renewed}");
    #[allow(clippy::cast_precision_loss)]
    let half = lifetime as f64 / 2.0;
    assert!(
        after >= half - 2.0,
        "PRODUCT: the {lifetime}s mapping was renewed {after:.1}s after its grant, before half its \
         lifetime (RFC 6887 §11.2.1, N-55): {renewed}"
    );
    assert!(
        renewed["answered"]["address"].as_str() == Some(server_text.as_str())
            && renewed["answered"]["rung"].as_str() == Some("PCP"),
        "PRODUCT: the renewal at {server} was not granted (a renewal under another nonce is \
         refused NOT_AUTHORIZED, §11.3): {renewed}"
    );
    let again = nonce();
    cleanup.probes.push(again);
    let said = pcp_map(server, again, port, PROBE_LIFETIME);
    println!("[proof] a fresh-nonce MAP after the renewal: {said:?}");
    assert!(
        matches!(said, Some((NOT_AUTHORIZED, _))),
        "PRODUCT: after the renewal the router no longer holds the daemon's mapping under its \
         nonce: a fresh-nonce MAP got {said:?}"
    );

    // ---- 4. deleted at stop ----
    let (stopped, exited) = cleanup.stop_daemon().expect("APPARATUS: the daemon handle");
    println!(
        "[proof] the daemon exited {exited:?} {:.2}s after SIGTERM",
        stopped.elapsed().as_secs_f64()
    );
    let last = nonce();
    cleanup.probes.push(last);
    let said = pcp_map(server, last, port, PROBE_LIFETIME);
    println!("[proof] a fresh-nonce MAP after the stop: {said:?}");
    assert!(
        matches!(said, Some((0, l)) if l > 0),
        "PRODUCT: after the daemon stopped, a fresh-nonce MAP for UDP {port} got {said:?}: the \
         daemon's mapping was not deleted (a held one refuses it, RFC 6887 §11.3; N-56)"
    );
    assert!(
        exited.is_some_and(|s| s.success()),
        "PRODUCT: the daemon did not exit cleanly after SIGTERM: {exited:?}"
    );
    println!("[proof] REAL ROUTER PASS: granted on PCP at {server}, renewed under its nonce, deleted at stop");
    // `cleanup` deletes this proof's MAPs on the way out.
}
