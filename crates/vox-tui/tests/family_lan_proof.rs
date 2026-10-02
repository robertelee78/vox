//! PRD-001 R28 / ADR-013 §"The family LAN" — **a room as a LAN**, proved without root:
//! four members of one room, each a real `vox lan up` — the shipped binary, driven as a person
//! would (ADR-018, "Only real use of the product is a test"). The room is made the way a
//! person makes it: an anchor (`vox node`), `vox id`, `vox trust add`, `vox daemon`,
//! `vox room create`, `vox room invite`, `vox room join`; then the daemons stop and each
//! member runs `vox lan up <room> --allow 5000 --stats-file … --metrics 127.0.0.1:0`.
//!
//! **The one piece that is not the shipped binary is root's.** `vox lan up` asks a helper,
//! over a Unix socket, for an interface, and the real helper (`sudo vox lan helper`) creates a
//! `utun`, which needs root. This proof never uses root, so the test answers on the helper's
//! socket itself, exactly as the helper does — `ok <name>` and one descriptor passed with
//! `SCM_RIGHTS` — and the descriptor is one end of a datagram socket pair, framed the way a
//! `utun` frames packets (a 4-byte address family ahead of each). The test holds the other
//! end: what it writes there is a packet the operating system sent out of the interface, and
//! what it reads is what the LAN delivered to the operating system. Everything between — the
//! room, the address plan, the routing, the app gate, the datagram flows, the flood fan-out
//! and its caps, the whitelist — is the shipped `vox`. Counters are read from the
//! `--stats-file` each `vox lan up` writes. The real helper and a real `utun` are
//! `scripts/family-lan-proof.sh`, which the decider runs as root.
//!
//! The scene: alice made the room; bob, dave and carol joined. alice, bob and dave trust
//! each other. **Nobody trusts carol**, and carol trusts all three — the eager outsider,
//! who dials everyone.
//!
//! What must hold, each counted:
//!
//! 1. **One plan.** All four nodes compute the same addresses: four distinct IPv4 hosts in
//!    one /24 of `100.64.0.0/10`, four IPv6 addresses in one `fd…/64`.
//! 2. **Links follow the gate.** alice, bob and dave each link to the other two; carol
//!    links to nobody, though she dials all three, watched for longer than her longest
//!    redial interval; and alice's running `vox lan up` answers `vox status --json` on its
//!    control socket (V030-04, #236) with carol's dials counted as refused as untrusted,
//!    and its `--metrics` endpoint answers with them counted among the refused app streams.
//! 3. **Unicast reaches the member holding the address, unchanged** — UDP over IPv4 and
//!    IPv6, a TCP segment, an ICMP echo, 1280-byte packets — and no member receives a
//!    packet addressed to another.
//! 4. **Floods reach every trusted member and nobody else**: mDNS `224.0.0.251`, SSDP
//!    `239.255.255.250`, the subnet broadcast and the limited broadcast. The subnet
//!    broadcast arrives as a limited broadcast with both checksums right.
//! 5. **The untrusted member gets nothing and gives nothing**: nothing carol's system sends
//!    reaches anyone, and nothing anyone sends reaches carol.
//! 6. **A member cannot speak as another**: bob's system sending as dave's address is
//!    dropped at alice.
//! 7. **Floods are capped**: 1000 mDNS packets at once deliver at most the burst plus the
//!    rate, and the rest are counted as capped.
//! 8. **Withdrawing trust ends the link**: once alice untrusts bob, nothing crosses between
//!    them, while dave still hears alice. alice runs `vox trust remove` while her LAN runs:
//!    the running `vox lan up` serves her profile's control socket (V030-04, #236), so the
//!    removal reaches it and ends the link **without a restart**, while bob's, which still
//!    trusts her, keeps running and redialling.
//! 9. **Only whitelisted ports are reachable** (the decider's rule, 2026-09-25). Every
//!    member runs with `--allow 5000`, so everything above goes to port 5000, and the
//!    floods in (4) go to ports 5353, 1900 and 9999, which are *not* listed. So discovery
//!    crosses the whitelist. Then:
//!    - UDP and a TCP SYN to the unlisted port 6000 deliver 0;
//!    - a SYN to 5000 and a non-SYN segment to 6000 (part of a connection that exists) are
//!      delivered;
//!    - a UDP reply to a port alice sent from is delivered, both after a unicast send and
//!      after a group send (an SSDP search answered by unicast);
//!    - UDP to a port alice never sent from delivers 0.
//!
//! And what the shipped binary shows about root's piece: `vox lan up` with no helper refuses
//! before touching the profile and names the command that starts one; the helper without
//! root refuses and listens nowhere; neither creates an interface.
//!
//! ## Why the scene is `#[ignore]`d, and macOS only
//! Production Argon2id on four profiles and a real proof of work per join; CI runs it in
//! release. `vox lan up` is built for macOS only (`lan_cli.rs`), so the scene is too.

#![cfg(target_os = "macos")]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::lan::packet::{ipv4_header_ok, ipv4_udp_ok, parse};
use vox_core::lan::{FLOOD_BURST, FLOOD_RATE};
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(120);
/// Production Argon2id and a real proof of work happen inside a join.
const SETUP: Duration = Duration::from_secs(180);
const ROOM_PASS: &str = "room passphrase";

// ---- packets, built the way a kernel would ----

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum()
}

fn ip4(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let total = 20 + body.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let hc = !fold(sum16(&p));
    p[10..12].copy_from_slice(&hc.to_be_bytes());
    p.extend_from_slice(body);
    p
}

fn udp_body(pseudo: &[u8], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut u = Vec::with_capacity(len);
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&(len as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let mut c = !fold(sum16(pseudo) + sum16(&u));
    if c == 0 {
        c = 0xffff;
    }
    u[6..8].copy_from_slice(&c.to_be_bytes());
    u
}

fn udp4(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp4s(src, dst, 40_000, dport, payload)
}

fn udp4s(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    ip4(17, src, dst, &udp_body(&pseudo, sport, dport, payload))
}

/// A TCP segment with `flags` (0x02 SYN, 0x10 ACK); its checksum is not needed here.
fn tcp4(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&40_001u16.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t.extend_from_slice(payload);
    ip4(6, src, dst, &t)
}

/// The port every member whitelists.
const LISTED: u16 = 5000;

fn udp6(src: Ipv6Addr, dst: Ipv6Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let u = udp_body(&pseudo, 40_000, dport, payload);
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p.extend_from_slice(&u);
    p
}

/// The packet's payload tag: the bytes after the IP and transport headers that this test
/// wrote there, which is how a delivered packet is matched to the one that was sent.
fn tag_of(p: &[u8]) -> String {
    let at = p
        .windows(4)
        .position(|w| w == b"TAG:")
        .map_or(p.len(), |i| i);
    let end = p[at..]
        .iter()
        .position(|b| *b == b'|')
        .map_or(p.len(), |i| at + i);
    String::from_utf8_lossy(&p[at..end]).into_owned()
}

/// A payload carrying `tag`, padded with a pattern to `len` bytes.
fn payload(tag: &str, len: usize) -> Vec<u8> {
    let mut v = format!("TAG:{tag}|").into_bytes();
    let mut i = 0u8;
    while v.len() < len {
        v.push(i);
        i = i.wrapping_add(7);
    }
    v
}

// ---- the room, made through the shipped binary ----

/// A one-shot `vox` verb with `stdin` piped in, in `data`'s profile.
fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn member_dir(tmp: &tempfile::TempDir, name: &str) -> PathBuf {
    let d = tmp.path().join(name);
    std::fs::create_dir_all(d.join("cfg")).unwrap();
    d
}

/// A `vox daemon`, answering `vox room list` before this returns.
fn daemon(name: &str, data: &Path, port: u16, anchor: &str, pass_file: &Path) -> VoxProc {
    let listen = format!("127.0.0.1:{port}");
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            &listen,
            "--anchor",
            anchor,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// `GET /metrics` from a `vox --metrics` endpoint at `addr`: the body.
fn scrape(addr: &str) -> String {
    use std::io::Read as _;
    let mut s = std::net::TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("PRODUCT: nothing answers at the metrics address {addr}: {e}"));
    s.set_read_timeout(Some(TIMEOUT)).ok();
    // In pieces, as a slow or proxied scraper's request arrives: the endpoint must read to the
    // end of the headers before it answers, or its close resets the connection (V030-23, #337).
    for piece in [
        "GET /metrics HTTP/1.0\r\n",
        &format!("Host: {addr}\r\n"),
        "\r\n",
    ] {
        s.write_all(piece.as_bytes()).unwrap_or_else(|e| {
            panic!("PRODUCT: the metrics endpoint at {addr} took no request: {e}")
        });
        s.flush().ok();
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut got = String::new();
    s.read_to_string(&mut got)
        .unwrap_or_else(|e| panic!("PRODUCT: the metrics endpoint at {addr} did not answer: {e}"));
    got.split_once("\r\n\r\n")
        .map_or(got.clone(), |(_, body)| body.to_owned())
}

/// Send `sig` to `p` by its PID and wait for it to exit, as a person's Ctrl-C or a service
/// manager's stop would; `Drop` kills it by PID if it has not.
fn stop(p: &mut VoxProc, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &p.child.id().to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "kill {sig} {}", p.name);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{} did not stop within 20 s of {sig}", p.name);
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait until nothing holds UDP `port`, so the next `vox` of that member can bind it.
fn port_free(port: u16) {
    let deadline = Instant::now() + TIMEOUT;
    while std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "127.0.0.1:{port} was never released"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Poll `f` until it is true, up to [`TIMEOUT`]; panic with `side` (`PRODUCT`,
/// `PRODUCT (staging)`) and `what` if it never is.
fn until(side: &str, what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !f() {
        assert!(
            Instant::now() < deadline,
            "{side}: timed out after {TIMEOUT:?} waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait long enough for anything in flight on loopback to land, and for every `vox lan up`
/// to have rewritten its stats file (twice a second) since.
fn settle() {
    std::thread::sleep(Duration::from_millis(2200));
}

// ---- root's piece, answered by the test: the helper's protocol, a socket pair for a utun ----

mod standin {
    use std::io::{BufRead as _, BufReader, IoSlice};
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

    /// `AF_INET` and `AF_INET6` as a `utun` frames them.
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 30;

    /// The operating system's side of one member's interface.
    #[derive(Clone, Default)]
    pub struct Os {
        /// The end the current `vox lan up` does not hold; replaced when it asks again.
        end: Arc<Mutex<Option<UnixDatagram>>>,
        /// Every packet the LAN delivered to this "operating system".
        pub got: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Every request line `vox lan up` sent the helper.
        pub asked: Arc<Mutex<Vec<String>>>,
    }

    impl Os {
        /// Answer on `socket` as `sudo vox lan helper` does, for as long as the test runs.
        pub fn serve(&self, socket: &Path) {
            let listener = UnixListener::bind(socket).expect("bind the helper socket");
            let me = self.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut line = String::new();
                    // `vox lan up` first connects only to see that a helper answers.
                    if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    me.asked.lock().unwrap().push(line.trim().to_owned());
                    let (theirs, ours) = UnixDatagram::pair().expect("socket pair");
                    for s in [&theirs, &ours] {
                        let _ = rustix::net::sockopt::set_socket_send_buffer_size(s, 1 << 20);
                        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(s, 4 << 20);
                    }
                    let fds = [theirs.as_fd()];
                    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                    let mut control = SendAncillaryBuffer::new(&mut space);
                    assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
                    rustix::net::sendmsg(
                        &stream,
                        &[IoSlice::new(b"ok utun-standin\n")],
                        &mut control,
                        SendFlags::empty(),
                    )
                    .expect("hand the descriptor over");
                    // As the helper does: hold our copy until `vox lan up` has its own
                    // (it closes the connection). Dropped while in flight, macOS's
                    // collector for descriptors in flight flushes it, and every write
                    // into the interface fails with EINVAL.
                    let _ = std::io::Read::read(&mut &stream, &mut [0u8; 1]);
                    drop(theirs);
                    let reader = ours.try_clone().expect("clone");
                    *me.end.lock().unwrap() = Some(ours);
                    let sink = Arc::clone(&me.got);
                    std::thread::spawn(move || {
                        let mut buf = vec![0u8; 4 + 65_535];
                        while let Ok(n) = reader.recv(&mut buf) {
                            if n == 0 {
                                return;
                            }
                            if n > 4 {
                                sink.lock().unwrap().push(buf[4..n].to_vec());
                            }
                        }
                    });
                }
            });
        }

        /// The operating system sends `p` out of the interface.
        pub fn emit(&self, p: &[u8]) {
            let family = if p[0] >> 4 == 6 { AF_INET6 } else { AF_INET };
            let mut framed = family.to_be_bytes().to_vec();
            framed.extend_from_slice(p);
            let guard = self.end.lock().unwrap();
            let end = guard.as_ref().expect("no interface was handed over");
            loop {
                match end.send(&framed) {
                    Ok(_) => return,
                    // The LAN has not read the last ones yet: wait, as a full queue would.
                    Err(e)
                        if e.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error())
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("writing into the interface: {e}"),
                }
            }
        }
    }
}

use standin::Os;

/// One member: a profile, its `vox lan up`, and the operating system behind its interface.
struct Host {
    name: &'static str,
    dir: PathBuf,
    id: String,
    /// The UDP port this member's machine listens on, as a machine keeps its own.
    port: u16,
    socket: PathBuf,
    stats_file: PathBuf,
    os: Os,
    lan: Option<VoxProc>,
    /// Where its running `vox lan up --metrics` serves its counters, as it printed it.
    metrics: Option<String>,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

impl Host {
    fn new(
        tmp: &tempfile::TempDir,
        name: &'static str,
        dir: PathBuf,
        id: String,
        port: u16,
    ) -> Self {
        let os = Os::default();
        let socket = tmp.path().join(format!("{name}.sock"));
        os.serve(&socket);
        Self {
            name,
            dir,
            id,
            port,
            socket,
            stats_file: tmp.path().join(format!("{name}.json")),
            os,
            lan: None,
            metrics: None,
            v4: Ipv4Addr::UNSPECIFIED,
            v6: Ipv6Addr::UNSPECIFIED,
        }
    }

    /// `vox lan up <room> --allow 5000 --metrics 127.0.0.1:0`, until it says it is up and has
    /// written its stats.
    fn up(&mut self, anchor: &str, room: &str) {
        let _ = std::fs::remove_file(&self.stats_file);
        port_free(self.port);
        let allow = LISTED.to_string();
        let listen = format!("127.0.0.1:{}", self.port);
        // While the interface is handed over, free local sockets as fast as possible, as a
        // busy machine does: each free runs macOS's collector for descriptors in flight,
        // so a descriptor left with no reference but the message is flushed every time
        // rather than now and then.
        let handing_over = Arc::new(AtomicBool::new(true));
        let churn = {
            let on = Arc::clone(&handing_over);
            std::thread::spawn(move || {
                while on.load(Ordering::Relaxed) {
                    drop(std::os::unix::net::UnixDatagram::unbound());
                }
            })
        };
        // From a file, never argv (V210-72: a room passphrase on the command line is refused).
        let pass_file = self.dir.join("room.pass");
        std::fs::write(&pass_file, ROOM_PASS).unwrap();
        let mut p = VoxProc::spawn(
            &format!("lan {}", self.name),
            &self.dir,
            &args(&[
                "lan",
                "up",
                room,
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--anchor",
                anchor,
                "--listen",
                &listen,
                "--helper-socket",
                self.socket.to_str().unwrap(),
                "--stats-file",
                self.stats_file.to_str().unwrap(),
                "--allow",
                &allow,
                "--metrics",
                "127.0.0.1:0",
            ]),
        );
        p.expect_within(SETUP, "vox lan up to come up", |l| {
            l.starts_with("vox lan up on ")
        });
        // Printed before the LAN comes up, so it is among the lines already read.
        self.metrics = p.seen.iter().find_map(|l| {
            l.strip_prefix("vox lan: metrics http://")
                .and_then(|r| r.strip_suffix("/metrics"))
                .map(str::to_owned)
        });
        handing_over.store(false, Ordering::Relaxed);
        churn.join().expect("the socket churn");
        self.lan = Some(p);
        let _ = self.stats();
    }

    /// The stats file `vox lan up` writes twice a second.
    fn stats(&self) -> serde_json::Value {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(v) = std::fs::read_to_string(&self.stats_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                return v;
            }
            assert!(
                Instant::now() < deadline,
                "{}'s vox lan up never wrote {}",
                self.name,
                self.stats_file.display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn counter(&self, k: &str) -> u64 {
        self.stats()[k]
            .as_u64()
            .unwrap_or_else(|| panic!("{}'s stats have no {k}", self.name))
    }

    fn links(&self) -> BTreeSet<String> {
        self.stats()["links"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn got(&self) -> Vec<Vec<u8>> {
        self.os.got.lock().unwrap().clone()
    }

    /// Packets delivered here whose tag starts with `prefix`.
    fn tagged(&self, prefix: &str) -> Vec<Vec<u8>> {
        self.got()
            .into_iter()
            .filter(|p| tag_of(p).starts_with(&format!("TAG:{prefix}")))
            .collect()
    }

    fn emit(&self, p: &[u8]) {
        self.os.emit(p);
    }
}

/// Each member's stats and everything its `vox lan up` said, so a red names its cause.
fn report(hosts: &mut [&mut Host]) {
    for h in hosts {
        let said = h.lan.as_mut().map(VoxProc::transcript).unwrap_or_default();
        eprintln!(
            "---- {} ({}) ----\nstats: {}\n{said}",
            h.name,
            h.id,
            h.stats()
        );
    }
}

fn addr_pair(v: &serde_json::Value) -> Option<(Ipv4Addr, Ipv6Addr)> {
    Some((
        v["v4"].as_str()?.parse().ok()?,
        v["v6"].as_str()?.parse().ok()?,
    ))
}

#[test]
#[ignore = "four real vox lan up with production Argon2id; CI runs it in release"]
fn a_room_is_a_lan_for_its_trusted_members_and_nobody_else() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();

    // ---- the room ----
    let mut anchor = VoxProc::spawn(
        "anchor",
        &member_dir(&tmp, "anchor"),
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    let names = ["alice", "bob", "dave", "carol"];
    let dirs: Vec<PathBuf> = names.iter().map(|n| member_dir(&tmp, n)).collect();
    let ids: Vec<String> = dirs
        .iter()
        .map(|d| {
            let (ok, out, err) = vox_once(d, &args(&["id"]));
            assert!(ok, "vox id: {err}");
            out.trim().to_owned()
        })
        .collect();
    // alice, bob and dave trust each other; carol trusts all three; nobody trusts carol.
    for (who, whom) in [
        (0, 1),
        (1, 0),
        (0, 2),
        (2, 0),
        (1, 2),
        (2, 1),
        (3, 0),
        (3, 1),
        (3, 2),
    ] {
        let (ok, out, err) = vox_once(
            &dirs[who],
            &args(&["trust", "add", &ids[whom], "--name", names[whom]]),
        );
        assert!(ok, "{} trusts {}: {out}{err}", names[who], names[whom]);
    }
    let pass_file = tmp.path().join("passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n{ROOM_PASS}\n")).unwrap();
    // Each member's machine keeps one UDP port, for its daemon and later its LAN, as a
    // person's does with the default `--listen`.
    let ports: Vec<u16> = names.iter().map(|_| free_udp_port()).collect();
    let mut daemons: Vec<VoxProc> = names
        .iter()
        .zip(&dirs)
        .zip(&ports)
        .map(|((n, d), port)| daemon(n, d, *port, &spec, &pass_file))
        .collect();
    let (ok, out, err) = vox_in(&dirs[0], &["room", "create", "--name", "family"], ROOM_PASS);
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&dirs[0], &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("family"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&dirs[0], &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    for (n, d) in names.iter().zip(&dirs).skip(1) {
        let deadline = Instant::now() + SETUP;
        loop {
            let (ok, out, err) = vox_in(
                d,
                &["room", "join", link.trim(), "--name", "family"],
                ROOM_PASS,
            );
            if ok {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {n} never joined: {out}{err}"
            );
            std::thread::sleep(Duration::from_secs(5));
        }
    }
    // Every member knows all four before the LANs start, so each plan starts complete.
    for (i, (n, d)) in names.iter().zip(&dirs).enumerate() {
        let deadline = Instant::now() + SETUP;
        loop {
            let (_, out, _) = vox_once(d, &args(&["status", "--json"]));
            let knows: BTreeSet<String> = serde_json::from_str::<serde_json::Value>(&out)
                .ok()
                .and_then(|s| {
                    s["rooms"][0]["members"].as_array().map(|ms| {
                        ms.iter()
                            .filter_map(|m| m["id"].as_str().map(str::to_owned))
                            .collect()
                    })
                })
                .unwrap_or_default();
            if ids
                .iter()
                .enumerate()
                .all(|(j, id)| j == i || knows.contains(id))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {n} knows only {knows:?} of the four members"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    for d in &mut daemons {
        stop(d, "-TERM");
    }
    drop(daemons);

    // ---- four LANs ----
    let mut hosts: Vec<Host> = names
        .iter()
        .zip(dirs)
        .zip(&ids)
        .zip(ports)
        .map(|(((n, d), id), port)| Host::new(&tmp, n, d, id.clone(), port))
        .collect();
    for h in &mut hosts {
        h.up(&spec, &room);
    }
    let [a, b, d, c] = &mut hosts[..] else {
        unreachable!()
    };

    // ---- 1. one plan ----
    until("PRODUCT", "all four plans to hold all four members", || {
        [&*a, &*b, &*d, &*c].iter().all(|h| {
            h.stats()["members"]
                .as_object()
                .is_some_and(|m| m.len() == 4)
        })
    });
    let plan = a.stats();
    for h in [&*b, &*d, &*c] {
        let s = h.stats();
        for k in ["subnet_v4", "prefix_v6", "members"] {
            assert_eq!(s[k], plan[k], "{}'s {k} differs from alice's", h.name);
        }
    }
    for h in [&mut *a, &mut *b, &mut *d, &mut *c] {
        let s = h.stats();
        let (v4, v6) = addr_pair(&s["addresses"])
            .unwrap_or_else(|| panic!("{} has no addresses: {s}", h.name));
        assert_eq!(
            s["members"][h.id.as_str()],
            s["addresses"],
            "{}'s own addresses are not its plan's",
            h.name
        );
        (h.v4, h.v6) = (v4, v6);
    }
    let v4s: BTreeSet<Ipv4Addr> = [&*a, &*b, &*d, &*c].iter().map(|h| h.v4).collect();
    let v6s: BTreeSet<Ipv6Addr> = [&*a, &*b, &*d, &*c].iter().map(|h| h.v6).collect();
    let subnet: Ipv4Addr = plan["subnet_v4"]
        .as_str()
        .and_then(|s| s.strip_suffix("/24"))
        .and_then(|s| s.parse().ok())
        .expect("a /24");
    let prefix: Ipv6Addr = plan["prefix_v6"]
        .as_str()
        .and_then(|s| s.strip_suffix("/64"))
        .and_then(|s| s.parse().ok())
        .expect("a /64");
    let net = subnet.octets();
    eprintln!(
        "[plan] /24 {subnet}  /64 {prefix}  v4 {v4s:?}  v6 {v6s:?}; helper asked for {:?}",
        [&*a, &*b, &*d, &*c]
            .iter()
            .map(|h| h.os.asked.lock().unwrap().clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        (v4s.len(), v6s.len()),
        (4, 4),
        "four distinct addresses each"
    );
    assert!(net[0] == 100 && (64..128).contains(&net[1]) && net[3] == 0);
    assert!(v4s
        .iter()
        .all(|v| v.octets()[..3] == net[..3] && (1..=254).contains(&v.octets()[3])));
    assert!(v6s
        .iter()
        .all(|v| v.octets()[..8] == prefix.octets()[..8] && v.octets()[0] == 0xfd));
    let broadcast = Ipv4Addr::new(net[0], net[1], net[2], 255);

    // ---- 2. links follow the gate ----
    let want = |x: &[&String]| x.iter().map(|s| (*s).clone()).collect::<BTreeSet<_>>();
    let deadline = Instant::now() + TIMEOUT;
    while !(a.links() == want(&[&b.id, &d.id])
        && b.links() == want(&[&a.id, &d.id])
        && d.links() == want(&[&a.id, &b.id]))
    {
        if Instant::now() >= deadline {
            eprintln!("---- the anchor ----\n{}", anchor.transcript());
            report(&mut [&mut *a, &mut *b, &mut *d, &mut *c]);
            panic!(
                "PRODUCT (staging): timed out after {TIMEOUT:?} waiting for the three trusted \
                 members to link to each other, so the gate on carol cannot be judged"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // carol dials everyone she trusts from the moment her LAN starts, and redials at most
    // 8 s apart: watched for longer than that, she must never hold a link.
    let watched = Instant::now();
    while watched.elapsed() < Duration::from_secs(10) {
        assert!(
            c.links().is_empty(),
            "PRODUCT: carol, whom nobody trusts, linked to {:?}",
            c.links()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!(
        "[links] alice {} bob {} dave {} carol {} (carol watched for {:?})",
        a.links().len(),
        b.links().len(),
        d.links().len(),
        c.links().len(),
        watched.elapsed()
    );
    assert!(
        c.links().is_empty(),
        "PRODUCT: carol, whom nobody trusts, linked to {:?}",
        c.links()
    );
    // alice's running LAN answers for her profile, and counts carol's dials as refused.
    let (ok, out, err) = vox_once(&a.dir, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: `vox status --json` while alice's LAN runs was refused: {out}{err}"
    );
    let status: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("PRODUCT: alice's `vox status --json` is not JSON: {e}\n{out}"));
    let untrusted = status["app"]["refused_untrusted"]
        .as_u64()
        .unwrap_or_else(|| panic!("PRODUCT: no app.refused_untrusted in alice's status:\n{out}"));
    eprintln!("[links] alice's `vox status --json`: app.refused_untrusted = {untrusted}");
    assert!(
        untrusted >= 1,
        "PRODUCT: alice counted none of carol's dials as refused as untrusted:\n{out}"
    );
    // And its metrics endpoint answers, with the same refusals counted.
    let at = a.metrics.clone().unwrap_or_else(|| {
        panic!("PRODUCT: alice's `vox lan up --metrics 127.0.0.1:0` never said where it serves metrics")
    });
    let scraped = scrape(&at);
    let refused = scraped
        .lines()
        .find_map(|l| l.strip_prefix("vox_app_streams_refused_total "))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            panic!("PRODUCT: alice's metrics at {at} have no vox_app_streams_refused_total:\n{scraped}")
        });
    eprintln!("[links] alice's metrics at {at}: vox_app_streams_refused_total = {refused}");
    assert!(
        refused >= untrusted,
        "PRODUCT: alice's metrics count {refused} refused app streams, fewer than the {untrusted} \
         her status counts as refused as untrusted"
    );

    // ---- 3. unicast reaches the member holding the address, unchanged ----
    let mut sent: Vec<(String, Vec<u8>, &'static str)> = Vec::new();
    for i in 0..50 {
        for (v4, v6, name) in [(b.v4, b.v6, "bob"), (d.v4, d.v6, "dave")] {
            let len = if i % 10 == 0 { 1280 - 28 } else { 64 };
            let p4 = udp4(a.v4, v4, 5000, &payload(&format!("uni/{name}/v4/{i}"), len));
            let p6 = udp6(a.v6, v6, 5000, &payload(&format!("uni/{name}/v6/{i}"), 64));
            sent.push((tag_of(&p4), p4.clone(), name));
            sent.push((tag_of(&p6), p6.clone(), name));
            a.emit(&p4);
            a.emit(&p6);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let tcp = tcp4(a.v4, b.v4, LISTED, 0x02, &payload("uni/bob/tcp/0", 60));
    let icmp = ip4(1, a.v4, b.v4, &payload("uni/bob/icmp/0", 60));
    sent.push((tag_of(&tcp), tcp.clone(), "bob"));
    sent.push((tag_of(&icmp), icmp.clone(), "bob"));
    a.emit(&tcp);
    a.emit(&icmp);
    settle();
    let (mut right, mut altered, mut misdelivered) = (0usize, 0usize, 0usize);
    for (h, name) in [(&*b, "bob"), (&*d, "dave"), (&*c, "carol")] {
        for p in h.tagged("uni/") {
            match sent.iter().find(|(t, _, _)| *t == tag_of(&p)) {
                Some((_, orig, to)) if *to == name => {
                    if *orig == p {
                        right += 1;
                    } else {
                        altered += 1;
                    }
                }
                _ => misdelivered += 1,
            }
        }
    }
    eprintln!(
        "[unicast] sent {} | arrived at the right member unchanged {right}, altered {altered}, \
         at the wrong member {misdelivered}",
        sent.len()
    );
    assert_eq!((altered, misdelivered), (0, 0));
    assert!(
        right * 100 >= sent.len() * 95,
        "only {right} of {} unicast packets arrived",
        sent.len()
    );
    for kind in ["uni/bob/tcp/0", "uni/bob/icmp/0"] {
        assert_eq!(b.tagged(kind).len(), 1, "{kind} did not reach bob");
    }

    // ---- 4. floods reach every trusted member and nobody else ----
    let groups: [(&str, Ipv4Addr, u16); 4] = [
        ("mdns", Ipv4Addr::new(224, 0, 0, 251), 5353),
        ("ssdp", Ipv4Addr::new(239, 255, 255, 250), 1900),
        ("subnet", broadcast, 9999),
        ("limited", Ipv4Addr::BROADCAST, 9999),
    ];
    for i in 0..10 {
        for (kind, dst, port) in groups {
            a.emit(&udp4(
                a.v4,
                dst,
                port,
                &payload(&format!("flood/{kind}/{i}"), 80),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    settle();
    for (kind, _, _) in groups {
        let (at_b, at_d, at_c) = (
            b.tagged(&format!("flood/{kind}/")).len(),
            d.tagged(&format!("flood/{kind}/")).len(),
            c.tagged(&format!("flood/{kind}/")).len(),
        );
        eprintln!("[flood] {kind}: 10 sent -> bob {at_b}, dave {at_d}, carol {at_c}");
        assert!(
            at_b >= 9 && at_d >= 9,
            "{kind} did not reach both trusted members"
        );
        assert_eq!(at_c, 0, "{kind} reached carol");
    }
    let subnet_floods = b.tagged("flood/subnet/");
    let rewritten = subnet_floods
        .iter()
        .filter(|p| {
            parse(p).is_some_and(|h| h.dst == IpAddr::V4(Ipv4Addr::BROADCAST))
                && ipv4_header_ok(p)
                && ipv4_udp_ok(p) == Some(true)
        })
        .count();
    eprintln!(
        "[flood] subnet broadcasts at bob as 255.255.255.255 with both checksums right: \
         {rewritten} of {}",
        subnet_floods.len()
    );
    assert_eq!(rewritten, subnet_floods.len());

    // ---- 5. the untrusted member gets nothing and gives nothing ----
    let carol_before = c.stats();
    for i in 0..20 {
        c.emit(&udp4(
            c.v4,
            a.v4,
            5000,
            &payload(&format!("carol/uni/{i}"), 64),
        ));
        c.emit(&udp4(
            c.v4,
            b.v4,
            5000,
            &payload(&format!("carol/uni/{i}"), 64),
        ));
        c.emit(&udp4(
            c.v4,
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            &payload(&format!("carol/mdns/{i}"), 64),
        ));
    }
    settle();
    let from_carol: usize = [&*a, &*b, &*d]
        .iter()
        .map(|h| {
            h.got()
                .iter()
                .filter(|p| parse(p).is_some_and(|x| x.src == IpAddr::V4(c.v4)))
                .count()
        })
        .sum();
    let carol_got = c.got().len();
    let cs = c.stats();
    let delta = |k: &str| cs[k].as_u64().unwrap() - carol_before[k].as_u64().unwrap();
    eprintln!(
        "[untrusted] carol sent 60 -> delivered anywhere {from_carol}; carol's LAN: \
         no_route +{}, floods +{} with {} copies; carol received {carol_got} packets in all",
        delta("no_route"),
        delta("floods"),
        cs["flood_copies"]
    );
    assert_eq!(from_carol, 0);
    assert_eq!(carol_got, 0);
    assert_eq!(cs["flood_copies"].as_u64(), Some(0));
    assert_eq!(delta("no_route"), 40);

    // ---- 6. a member cannot speak as another ----
    let spoofed_before = a.counter("spoofed");
    b.emit(&udp4(d.v4, a.v4, 5000, &payload("spoof/as-dave", 64)));
    b.emit(&udp6(d.v6, a.v6, 5000, &payload("spoof/as-dave-v6", 64)));
    settle();
    let spoofed = a.counter("spoofed") - spoofed_before;
    let landed = a.tagged("spoof/").len();
    eprintln!(
        "[spoof] bob sent 2 as dave -> alice dropped {spoofed} as spoofed, delivered {landed}"
    );
    assert_eq!(
        (spoofed, landed),
        (2, 0),
        "bob's packets as dave must be dropped at alice as spoofed, and none delivered"
    );

    // ---- 9. only whitelisted ports are reachable ----
    let filtered_before = b.counter("filtered");
    for i in 0..10 {
        a.emit(&udp4(
            a.v4,
            b.v4,
            6000,
            &payload(&format!("wl/udp-unlisted/{i}"), 64),
        ));
    }
    a.emit(&tcp4(
        a.v4,
        b.v4,
        6000,
        0x02,
        &payload("wl/syn-unlisted/0", 40),
    ));
    a.emit(&tcp4(
        a.v4,
        b.v4,
        LISTED,
        0x02,
        &payload("wl/syn-listed/0", 40),
    ));
    a.emit(&tcp4(
        a.v4,
        b.v4,
        6000,
        0x10,
        &payload("wl/ack-unlisted/0", 40),
    ));
    // alice sends from 41000 to bob and from 42000 to the SSDP group; bob answers
    // both, and also writes to 41001, a port alice never sent from.
    a.emit(&udp4s(a.v4, b.v4, 41_000, LISTED, &payload("wl/ask/0", 40)));
    a.emit(&udp4s(
        a.v4,
        Ipv4Addr::new(239, 255, 255, 250),
        42_000,
        1900,
        &payload("wl/search/0", 40),
    ));
    settle();
    b.emit(&udp4s(
        b.v4,
        a.v4,
        LISTED,
        41_000,
        &payload("wl/reply-unicast/0", 40),
    ));
    d.emit(&udp4s(
        d.v4,
        a.v4,
        1900,
        42_000,
        &payload("wl/reply-group/0", 40),
    ));
    b.emit(&udp4s(
        b.v4,
        a.v4,
        LISTED,
        41_001,
        &payload("wl/unasked/0", 40),
    ));
    settle();
    let n = |h: &Host, t: &str| h.tagged(&format!("wl/{t}/")).len();
    let wl = [
        ("udp to an unlisted port", n(b, "udp-unlisted"), 0),
        ("SYN to an unlisted port", n(b, "syn-unlisted"), 0),
        ("SYN to a listed port", n(b, "syn-listed"), 1),
        ("non-SYN to an unlisted port", n(b, "ack-unlisted"), 1),
        ("reply after a unicast send", n(a, "reply-unicast"), 1),
        ("reply after a group send", n(a, "reply-group"), 1),
        ("udp to a port never sent from", n(a, "unasked"), 0),
    ];
    for (what, got, want) in wl {
        eprintln!("[whitelist] {what}: delivered {got} (must be {want})");
    }
    let filtered = b.counter("filtered") - filtered_before;
    eprintln!("[whitelist] bob filtered {filtered} packets");
    for (what, got, want) in wl {
        assert_eq!(got, want, "{what}");
    }
    assert_eq!(filtered, 11);

    // ---- 7. floods are capped ----
    std::thread::sleep(Duration::from_millis(
        (FLOOD_BURST / FLOOD_RATE * 1000.0) as u64 + 500,
    ));
    let capped_before = a.counter("rate_capped");
    let t0 = Instant::now();
    for i in 0..1000 {
        a.emit(&udp4(
            a.v4,
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            &payload(&format!("storm/{i}"), 64),
        ));
    }
    let elapsed = t0.elapsed().as_secs_f64();
    settle();
    let at_b = b.tagged("storm/").len();
    let capped = a.counter("rate_capped") - capped_before;
    let bound = FLOOD_BURST + FLOOD_RATE * elapsed + 1.0;
    eprintln!(
        "[cap] 1000 floods in {elapsed:.3}s -> bob got {at_b} (bound {bound:.0}), capped at alice {capped}"
    );
    assert!(
        (at_b as f64) <= bound,
        "bob got {at_b}, over the bound {bound:.0}"
    );
    assert!(at_b >= 150, "the burst itself did not arrive: {at_b}");
    assert!(capped as f64 >= 1000.0 - bound);

    // ---- 8. withdrawing trust ends the link ----
    // alice's LAN keeps running: the removal reaches it through its control socket.
    let (live, out, said) = vox_once(&a.dir, &args(&["trust", "remove", &b.id]));
    eprintln!(
        "[withdrawn] `vox trust remove` while alice's LAN runs: ok={live}: {}{}",
        out.trim(),
        said.trim()
    );
    assert!(
        live,
        "PRODUCT: `vox trust remove` did not reach alice's running LAN: {out}{said}"
    );
    until(
        "PRODUCT",
        "alice to link with dave again, and alice and bob not at all, after she untrusted bob",
        || a.links() == want(&[&d.id]) && !b.links().contains(&a.id),
    );
    for i in 0..20 {
        b.emit(&udp4(
            b.v4,
            a.v4,
            5000,
            &payload(&format!("after/uni/{i}"), 64),
        ));
        a.emit(&udp4(
            a.v4,
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            &payload(&format!("after/mdns/{i}"), 64),
        ));
        std::thread::sleep(Duration::from_millis(10));
    }
    settle();
    let (at_a, at_b, at_d) = (
        a.tagged("after/uni/").len(),
        b.tagged("after/mdns/").len(),
        d.tagged("after/mdns/").len(),
    );
    eprintln!(
        "[withdrawn] bob->alice {at_a}/20, alice's floods at bob {at_b}/20, at dave {at_d}/20; \
         links: alice {:?} bob {:?}",
        a.links(),
        b.links()
    );
    assert_eq!(
        (at_a, at_b),
        (0, 0),
        "PRODUCT: after alice untrusted bob, {at_a}/20 of bob's packets reached alice and \
         {at_b}/20 of alice's floods reached bob; both must be 0"
    );
    assert!(
        at_d >= 18,
        "PRODUCT: after alice untrusted bob, dave stopped hearing her: {at_d}/20 of her floods \
         reached him"
    );
    drop(anchor);
}

fn interfaces() -> String {
    String::from_utf8(
        Command::new("/sbin/ifconfig")
            .arg("-l")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
}

/// With no helper running, `vox lan up` refuses before it touches the profile, names the
/// command that starts the helper, and creates no interface.
#[test]
fn lan_up_without_a_helper_refuses_and_creates_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("no-helper.sock");
    let before = interfaces();
    let out = Command::new(VOX)
        .args(["lan", "up", "family", "--helper-socket"])
        .arg(&socket)
        .env("VOX_DATA_DIR", tmp.path().join("data"))
        .env("VOX_CONFIG_DIR", tmp.path().join("cfg"))
        .output()
        .unwrap();
    let after = interfaces();
    let err = String::from_utf8_lossy(&out.stderr);
    eprintln!("[vox lan up] exit {:?}: {err}", out.status.code());
    assert!(!out.status.success());
    assert!(
        err.contains("sudo vox lan helper --socket"),
        "it did not say how to start the helper: {err}"
    );
    assert_eq!(before, after, "an interface appeared or went away");
    assert!(
        !tmp.path().join("data").exists() && !tmp.path().join("cfg").exists(),
        "it touched the profile before refusing"
    );
}

/// The helper, run without root, refuses and leaves no socket behind — it is the one
/// piece that needs root, and says so.
#[test]
fn the_helper_without_root_refuses_and_listens_nowhere() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("helper.sock");
    let before = interfaces();
    let out = Command::new(VOX)
        .args(["lan", "helper", "--socket"])
        .arg(&socket)
        .env("VOX_DATA_DIR", tmp.path().join("data"))
        .env("VOX_CONFIG_DIR", tmp.path().join("cfg"))
        .env("SUDO_UID", "501")
        .env("SUDO_GID", "20")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    eprintln!("[vox lan helper] exit {:?}: {err}", out.status.code());
    assert!(!out.status.success());
    assert!(err.contains("sudo vox lan helper"), "{err}");
    assert!(!socket.exists(), "it listened anyway");
    assert_eq!(before, interfaces());
}
