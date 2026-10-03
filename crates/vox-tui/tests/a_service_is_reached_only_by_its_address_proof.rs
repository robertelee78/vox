//! V030-25 (#339), with PRD-001 R44 (#94) — **a shared service is reached as
//! `<service>.<node>.<room>.vox`, and only that way.** Proved with the shipped binary only: an
//! anchor, alice's `vox serve`, and bob's and carol's `vox daemon`s, `vox room join`, `vox trust
//! add`, `vox service list/add` and `vox up`, every one a `vox` verb.
//!
//! The scene: alice shares `nas-ssh` and `nas-nfs` in one room with `vox serve nas-ssh=… nas-nfs=…`
//! — two echo services that answer `ssh:` and `nfs:`. bob joins it and calls the room `fam` and
//! alice `nas-box`; carol joins it and calls them `house` and `ally`. alice trusts both: reach is
//! the host's decision (ADR-017 decision 3).
//!
//! What must hold:
//!
//! 1. bob reaches each service as `<service>.nas-box.fam.vox`, and as `vox serve` printed it (the
//!    fingerprints in the node and room places).
//! 2. carol reaches the same services through her own aliases, `<service>.ally.house.vox`.
//! 3. `fam.vox` (a room), `nas-box.fam.vox` (a node) and `<room-id>.vox` (the form R44 removed
//!    with the genesis grant behind it) resolve to nothing: no connection, and what `vox up` says
//!    about them names no service.
//! 4. `vox service list` lists both services for each member, each with its address in that
//!    member's own words and who shared it.
//! 5. a second share under a taken name is refused, naming it; the first still answers.
//! 6. `vox serve` with a bare port is refused, saying how to name the share.
//! 7. `vox forward` takes the address and nothing else (decider, 2026-10-03: "address only"):
//!    `vox forward nas-ssh.nas-box.fam.vox` carries bob to alice's ssh service, and the form that
//!    names a room, a member and a service is refused.
//! 8. An address naming no share in a room bob has synced is refused at once, saying so: within
//!    [`IMMEDIATE`], PRD-001 R23's bound (#69), with no wait for a share that is not coming.
//! 9. The same for UDP: alice also shares `nas-dns` over UDP. `vox forward nas-dns.nas-box.fam.vox`
//!    carries bob's datagrams to it and back, and an address naming no UDP share (`dns.…`) is
//!    refused at once, saying so, rather than bound and its datagrams dropped.
//!
//! **A red names its side.** A `vox` command that fails while the scene is set is PRODUCT
//! (staging); what this proof claims is PRODUCT, quoting what vox said; the proof's own files,
//! ports and echo services are APPARATUS.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{after_label, args, VoxProc, IDENTITY, VOX};

/// PRD-001 R23's bound for a refusal (#69's `tunnel_honesty_proof`): it fails at once.
const IMMEDIATE: Duration = Duration::from_secs(2);

/// How long setting the scene may take at each step.
const SETUP: Duration = Duration::from_secs(90);

/// A one-shot `vox` verb in `dir`'s profile, `stdin` piped in when given.
fn vox(dir: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write to vox's stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: a free UDP port")
        .port()
}

/// A profile with an identity; its directory and fingerprint.
fn profile(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: a profile directory");
    let (ok, out, err) = vox(&dir, &["id", "--listen", "127.0.0.1:0"], None);
    let fp = out.trim().to_owned();
    assert!(
        ok && fp.len() == 52,
        "PRODUCT (staging): vox id ({name}): {out}{err}"
    );
    (dir, fp)
}

fn trust(dir: &Path, who: &str, fp: &str, as_name: &str) {
    let (ok, out, err) = vox(
        dir,
        &[
            "trust",
            "add",
            fp,
            "--name",
            as_name,
            "--listen",
            "127.0.0.1:0",
        ],
        None,
    );
    assert!(ok, "PRODUCT (staging): {who} trusts {as_name}: {out}{err}");
}

/// `vox daemon` on `dir`, its identity passphrase from a file; returned once it answers.
fn daemon(name: &str, dir: &Path, anchor: &str) -> VoxProc {
    let pass_file = dir.join("passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("APPARATUS: write the passphrase file");
    let mut p = VoxProc::spawn(
        name,
        dir,
        &args(&[
            "daemon",
            "--listen",
            &format!("127.0.0.1:{}", free_udp_port()),
            "--anchor",
            anchor,
            "--passphrase-file",
            pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while !vox(dir, &["room", "list"], None).0 {
        if Instant::now() >= deadline {
            panic!(
                "PRODUCT (staging): {name}'s daemon never answered `vox room list`. It said:\n{}",
                p.transcript()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    p
}

/// A TCP service that answers each line with `<owner>:<line>`.
fn echo(owner: &'static str) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("APPARATUS: an echo listener");
    let at = l.local_addr().expect("APPARATUS: the echo's address");
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    let mut out = format!("{owner}:").into_bytes();
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    at
}

/// A UDP service that answers each datagram with `<owner>:<datagram>`.
fn udp_echo(owner: &'static str) -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: a UDP echo socket");
    let at = sock
        .local_addr()
        .expect("APPARATUS: the UDP echo's address");
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let mut out = format!("{owner}:").into_bytes();
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, from);
        }
    });
    at
}

/// `vox forward <address>` on `dir`, expected to be refused: whether it exited refused within
/// 30 s, how long it took, and what it said.
fn forward_refused(dir: &Path, who: &str, address: &str) -> (bool, Duration, String) {
    let t = Instant::now();
    let mut p = VoxProc::spawn(who, dir, &args(&["forward", address, "127.0.0.1:0"]));
    let status = loop {
        match p.child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if t.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => break None,
            Err(e) => panic!("APPARATUS: wait for {who}: {e}"),
        }
    };
    let took = t.elapsed();
    std::thread::sleep(Duration::from_millis(200));
    let said = p.transcript();
    (status.is_some_and(|st| !st.success()), took, said)
}

/// A CONNECT through the proxy to `host`; the stream, or the SOCKS reply code.
fn socks(proxy: SocketAddr, host: &str) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect(proxy).expect("PRODUCT: `vox up`'s proxy refused a connection");
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .expect("APPARATUS: set a read timeout");
    s.write_all(&[0x05, 0x01, 0x00])
        .expect("PRODUCT: `vox up`'s proxy closed on the SOCKS greeting");
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)
        .expect("PRODUCT: `vox up`'s proxy did not answer the SOCKS greeting");
    let mut req = vec![
        0x05,
        0x01,
        0x00,
        0x03,
        u8::try_from(host.len()).expect("APPARATUS: a name of at most 255 bytes"),
    ];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&22u16.to_be_bytes());
    s.write_all(&req)
        .expect("PRODUCT: `vox up`'s proxy closed on the CONNECT");
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox up`'s proxy did not answer CONNECT {host}: {e}"));
    if head[1] != 0 {
        return Err(head[1]);
    }
    let skip = match head[3] {
        0x01 => 6,
        0x04 => 18,
        _ => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)
                .expect("PRODUCT: `vox up`'s proxy cut its CONNECT reply short");
            usize::from(l[0]) + 2
        }
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)
        .expect("PRODUCT: `vox up`'s proxy cut its CONNECT reply short");
    Ok(s)
}

/// Which service answers at `name` through the proxy: the echo's owner, or the SOCKS code.
fn who_answers(proxy: SocketAddr, name: &str) -> Result<String, u8> {
    let mut s = socks(proxy, name)?;
    s.write_all(b"hello\n")
        .unwrap_or_else(|e| panic!("PRODUCT: {name}'s tunnel closed before a line was sent: {e}"));
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(s), &mut line)
        .unwrap_or_else(|e| panic!("PRODUCT: no answer came back through {name}: {e}"));
    Ok(line.split(':').next().unwrap_or("").to_owned())
}

/// `vox up` in the daemon holding `dir`'s profile, and the proxy's address.
fn up(name: &str, dir: &Path) -> (VoxProc, SocketAddr) {
    let mut p = VoxProc::spawn(name, dir, &args(&["up", "--bind", "127.0.0.1:0"]));
    let first = p.expect_line("PRODUCT (staging): vox up's address", |l| {
        l.starts_with("vox up on ")
    });
    let proxy = first
        .split_whitespace()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT (staging): vox up said {first:?}"));
    (p, proxy)
}

/// `vox service list <room>` on `dir`, polled until `want` all appear (the shares reach a member
/// with the room's log); what it last said.
fn listed(dir: &Path, room: &str, want: &[String]) -> (bool, String) {
    let deadline = Instant::now() + SETUP;
    loop {
        let (ok, out, err) = vox(dir, &["service", "list", room], None);
        let said = format!("{out}{err}");
        if ok && want.iter().all(|w| said.contains(w.as_str())) {
            return (true, said);
        }
        if Instant::now() >= deadline {
            return (false, said);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore = "an anchor, a vox serve, two vox daemons and real child processes; run on demand"]
fn a_shared_service_is_reached_as_service_node_room_and_only_that_way() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (ssh_at, nfs_at, dns_at) = (echo("ssh"), echo("nfs"), udp_echo("dns"));

    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: the anchor's directory");
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("PRODUCT (staging): an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let (alice_dir, alice_fp) = profile(tmp.path(), "alice");
    let (bob_dir, bob_fp) = profile(tmp.path(), "bob");
    let (carol_dir, carol_fp) = profile(tmp.path(), "carol");
    trust(&alice_dir, "alice", &bob_fp, "bob");
    trust(&alice_dir, "alice", &carol_fp, "carol");
    trust(&bob_dir, "bob", &alice_fp, "nas-box");
    trust(&carol_dir, "carol", &alice_fp, "ally");

    // (6) A bare port is refused, saying how to name the share — before anything is made.
    let (bare_ok, bare_out, bare_err) = vox(
        &alice_dir,
        &[
            "serve",
            &ssh_at.port().to_string(),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        None,
    );

    // alice shares both services in one room.
    let mut serve = VoxProc::spawn(
        "alice serve",
        &alice_dir,
        &args(&[
            "serve",
            &format!("nas-ssh={}", ssh_at.port()),
            &format!("nas-nfs={}", nfs_at.port()),
            &format!("nas-dns={}/udp", dns_at.port()),
            "--anchor",
            &spec,
            "--listen",
            &format!("127.0.0.1:{}", free_udp_port()),
        ]),
    );
    let room = after_label(
        &serve.expect_line("PRODUCT (staging): vox serve's room", |l| {
            l.starts_with("room ")
        }),
        "room",
    );
    let address = after_label(
        &serve.expect_line("PRODUCT (staging): vox serve's address", |l| {
            l.starts_with("address ")
        }),
        "address",
    );
    let passphrase = after_label(
        &serve.expect_line("PRODUCT (staging): vox serve's passphrase", |l| {
            l.starts_with("passphrase ")
        }),
        "passphrase",
    );
    let printed_ssh = format!("nas-ssh.{alice_fp}.{room}.vox");
    let printed_line = serve.expect_line("PRODUCT: vox serve prints nas-ssh's address", |l| {
        l.starts_with("sharing ") && l.contains("as nas-ssh.")
    });

    // bob and carol join, each under their own name for the room.
    let mut bob_daemon = daemon("bob", &bob_dir, &spec);
    let mut carol_daemon = daemon("carol", &carol_dir, &spec);
    for (who, dir, local) in [("bob", &bob_dir, "fam"), ("carol", &carol_dir, "house")] {
        let (ok, out, err) = vox(
            dir,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                &address,
                "--name",
                local,
            ],
            Some(&format!("{passphrase}\n")),
        );
        assert!(
            ok,
            "PRODUCT (staging): {who} joins alice's room as {local}: {out}{err}\nalice's vox serve \
             said:\n{}",
            serve.transcript()
        );
    }

    // (4) Each lists both services, in its own words, with who shared them.
    let bob_wants = [
        "nas-ssh.nas-box.fam.vox  by nas-box".to_owned(),
        "nas-nfs.nas-box.fam.vox  by nas-box".to_owned(),
    ];
    let carol_wants = [
        "nas-ssh.ally.house.vox  by ally".to_owned(),
        "nas-nfs.ally.house.vox  by ally".to_owned(),
    ];
    let bob_list = listed(&bob_dir, &room, &bob_wants);
    let carol_list = listed(&carol_dir, &room, &carol_wants);

    let (bob_up, bob_proxy) = up("bob up", &bob_dir);
    let (mut carol_up, carol_proxy) = up("carol up", &carol_dir);

    // (1), (2): every address in each member's words, and the printed one.
    let reached: Vec<(String, Result<String, u8>)> = [
        (bob_proxy, "nas-ssh.nas-box.fam.vox".to_owned()),
        (bob_proxy, "nas-nfs.nas-box.fam.vox".to_owned()),
        (bob_proxy, printed_ssh.clone()),
        (bob_proxy, format!("nas-nfs.{alice_fp}.{room}.vox")),
        (carol_proxy, "nas-ssh.ally.house.vox".to_owned()),
        (carol_proxy, "nas-nfs.ally.house.vox".to_owned()),
    ]
    .into_iter()
    .map(|(proxy, n)| {
        let r = who_answers(proxy, &n);
        (n, r)
    })
    .collect();

    // (3) Nothing shorter is an address.
    let before_nothing = Instant::now();
    let nothing: Vec<(String, Result<String, u8>)> = [
        "fam.vox".to_owned(),
        "nas-box.fam.vox".to_owned(),
        format!("{room}.vox"),
        format!("{alice_fp}.{room}.vox"),
    ]
    .into_iter()
    .map(|n| {
        let r = who_answers(bob_proxy, &n);
        (n, r)
    })
    .collect();
    std::thread::sleep(Duration::from_millis(500));
    let up_said: Vec<String> = bob_up.said_since(before_nothing);

    // (5) A second share under a taken name is refused, naming it.
    let (dup_ok, dup_out, dup_err) = vox(
        &alice_dir,
        &["service", "add", &room, "nas-ssh", &nfs_at.to_string()],
        None,
    );
    let after_dup = who_answers(bob_proxy, "nas-ssh.nas-box.fam.vox");

    eprintln!(
        "bare serve: ok={bare_ok} {bare_out}{bare_err}\nprinted: {printed_line}\nbob's list: \
         {bob_list:?}\ncarol's list: {carol_list:?}\nreached: {reached:?}\nnothing: {nothing:?}\n\
         bob's vox up said: {up_said:?}\nsecond nas-ssh: ok={dup_ok} {dup_out}{dup_err}\n\
         nas-ssh after it: {after_dup:?}"
    );

    assert!(
        !bare_ok
            && format!("{bare_out}{bare_err}").contains("has no name")
            && format!("{bare_out}{bare_err}").contains("vox serve ssh=22"),
        "PRODUCT: `vox serve <port>` without a name must be refused, saying how to name it: \
         {bare_out}{bare_err}"
    );
    assert!(
        printed_line.contains(&printed_ssh),
        "PRODUCT: vox serve must print nas-ssh's address with its fingerprint and the room id \
         ({printed_ssh}); it printed {printed_line:?}"
    );
    for (n, r) in &reached {
        let want = if n.starts_with("nas-ssh.") {
            "ssh"
        } else {
            "nfs"
        };
        assert_eq!(
            r.as_deref(),
            Ok(want),
            "PRODUCT: {n} did not reach alice's {want} service"
        );
    }
    for (n, r) in &nothing {
        assert!(
            r.is_err(),
            "PRODUCT: {n} must resolve to nothing, but connected and was answered by {r:?}"
        );
    }
    for line in &up_said {
        assert!(
            !line.contains("nas-ssh") && !line.contains("nas-nfs"),
            "PRODUCT: what `vox up` says about a name that resolves to nothing must name no \
             service: {line:?}"
        );
    }
    assert!(
        bob_list.0,
        "PRODUCT: bob's `vox service list` does not show both services in his own words \
         ({bob_wants:?}): {}",
        bob_list.1
    );
    assert!(
        carol_list.0,
        "PRODUCT: carol's `vox service list` does not show both services in her own words \
         ({carol_wants:?}): {}",
        carol_list.1
    );
    assert!(
        !dup_ok
            && format!("{dup_out}{dup_err}").contains("nas-ssh")
            && format!("{dup_out}{dup_err}").contains("already share a service under that name"),
        "PRODUCT: a second share named nas-ssh must be refused, naming it: {dup_out}{dup_err}"
    );
    assert_eq!(
        after_dup.as_deref(),
        Ok("ssh"),
        "PRODUCT: after the refused second nas-ssh, nas-ssh must still reach the first"
    );
    // (7) `vox forward` by the address, through bob's daemon; and the three-word form refused.
    let mut fwd = VoxProc::spawn(
        "bob forward",
        &bob_dir,
        &args(&["forward", "nas-ssh.nas-box.fam.vox", "127.0.0.1:0"]),
    );
    let bound_line = fwd.expect_line("PRODUCT: `vox forward <address>` binds", |l| {
        l.starts_with("vox: forwarding ")
    });
    let bound: SocketAddr = bound_line
        .split_whitespace()
        .nth(2)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: vox forward said {bound_line:?}"));
    let forwarded = {
        let mut s = TcpStream::connect(bound)
            .unwrap_or_else(|e| panic!("PRODUCT: the forward at {bound} refused: {e}"));
        s.set_read_timeout(Some(vox_core::node::up::HOST_PATIENCE))
            .expect("APPARATUS: set a read timeout");
        s.write_all(b"hello\n")
            .unwrap_or_else(|e| panic!("PRODUCT: the forward closed before a line: {e}"));
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(s), &mut line)
            .unwrap_or_else(|e| panic!("PRODUCT: nothing came back through the forward: {e}"));
        line
    };
    // Spawned, not waited for: a form that is accepted forwards until stopped, so it is judged by
    // whether it exits refused within a bound, and by what it said.
    let mut three = VoxProc::spawn(
        "bob three-word forward",
        &bob_dir,
        &args(&["forward", &room, &alice_fp, "nas-ssh", "127.0.0.1:0"]),
    );
    let three_deadline = Instant::now() + Duration::from_secs(15);
    let three_status = loop {
        match three.child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() < three_deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => break None,
            Err(e) => panic!("APPARATUS: wait for the three-word forward: {e}"),
        }
    };
    std::thread::sleep(Duration::from_millis(200));
    let three_said = three.transcript();
    let three_ok = three_status.is_none_or(|st| st.success())
        || three_said.contains("vox: forwarding")
        || three_said.contains('→');
    let (three_out, three_err) = (three_said, String::new());
    drop(three);
    eprintln!(
        "forward by address: {bound_line:?} answered {forwarded:?}\nthree-word forward: \
         ok={three_ok} {three_out}{three_err}"
    );
    assert!(
        forwarded.starts_with("ssh:"),
        "PRODUCT: `vox forward nas-ssh.nas-box.fam.vox` did not carry bob to alice's ssh service: \
         {forwarded:?}"
    );
    assert!(
        !three_ok,
        "PRODUCT: `vox forward <room> <member> <service>` must be refused — the address is the only \
         form: {three_out}{three_err}"
    );
    drop(fwd);

    // (9) UDP: the share by its address carries datagrams; a name no UDP share carries is refused.
    let mut dns_fwd = VoxProc::spawn(
        "bob forward nas-dns",
        &bob_dir,
        &args(&["forward", "nas-dns.nas-box.fam.vox", "127.0.0.1:0"]),
    );
    let dns_line = dns_fwd.expect_line("PRODUCT: `vox forward` of a UDP share binds", |l| {
        l.starts_with("vox: forwarding ")
    });
    let dns_bound: SocketAddr = dns_line
        .split_whitespace()
        .nth(2)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: vox forward said {dns_line:?}"));
    let dns_answer = {
        let c = std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: a UDP client");
        c.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("APPARATUS: a UDP read timeout");
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let _ = c.send_to(b"query", dns_bound);
            if let Ok((n, _)) = c.recv_from(&mut buf) {
                break Some(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
            if Instant::now() >= deadline {
                break None;
            }
        }
    };
    drop(dns_fwd);
    let (dns_refused, dns_took, dns_said) =
        forward_refused(&bob_dir, "bob forward dns", "dns.nas-box.fam.vox");
    eprintln!(
        "forward nas-dns: {dns_line:?} answered {dns_answer:?}\nforward dns (no such share): \
         refused={dns_refused} after {dns_took:?}: {dns_said}"
    );
    assert!(
        dns_line.contains("udp/nas-dns") && dns_answer.as_deref() == Some("dns:query"),
        "PRODUCT: `vox forward nas-dns.nas-box.fam.vox` must carry datagrams to alice's UDP share \
         and back: {dns_line:?} answered {dns_answer:?}"
    );
    assert!(
        dns_refused && dns_said.contains("shares no service called `dns`"),
        "PRODUCT: a forward to an address naming no UDP share must be refused, saying so, not \
         bound with its datagrams dropped: {dns_said}"
    );
    assert!(
        dns_took <= IMMEDIATE,
        "PRODUCT: a forward to an address naming no UDP share took {dns_took:?} to be refused; R23 \
         bounds a refusal at {IMMEDIATE:?}"
    );
    // (8) No share of that name, in a room bob has synced: refused at once, through his daemon.
    let t_absent = Instant::now();
    let mut absent = VoxProc::spawn(
        "bob forward nas-ftp",
        &bob_dir,
        &args(&["forward", "nas-ftp.nas-box.fam.vox", "127.0.0.1:0"]),
    );
    let absent_status = loop {
        match absent.child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if t_absent.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => break None,
            Err(e) => panic!("APPARATUS: wait for the forward to nas-ftp: {e}"),
        }
    };
    let absent_took = t_absent.elapsed();
    std::thread::sleep(Duration::from_millis(200));
    let absent_said = absent.transcript();
    drop(absent);
    eprintln!("forward to nas-ftp: {absent_status:?} after {absent_took:?}: {absent_said}");
    assert!(
        absent_status.is_some_and(|st| !st.success())
            && absent_said.contains("shares no service called `nas-ftp`"),
        "PRODUCT: a forward to an address naming no share must be refused, saying so: \
         {absent_status:?} {absent_said}"
    );
    assert!(
        absent_took <= IMMEDIATE,
        "PRODUCT: a forward to an address naming no share in a synced room took {absent_took:?} to \
         be refused; R23 bounds a refusal at {IMMEDIATE:?}"
    );
    eprintln!(
        "[proof] 2 services reached by 6 addresses through 2 members' own words; 4 shorter names \
         resolved to nothing; a duplicate name and a bare port refused; forward by address only; absent TCP and UDP shares refused at once"
    );
    let _ = (
        bob_daemon.transcript(),
        carol_daemon.transcript(),
        carol_up.transcript(),
    );
    drop((serve, bob_up, carol_up, bob_daemon, carol_daemon, anchor));
}
