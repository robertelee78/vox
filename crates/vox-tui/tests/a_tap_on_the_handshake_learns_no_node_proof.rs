//! ADR-011 requirement 27, ADR-026 §6 — **a passive observer of a connection learns no node's
//! fingerprint from it**, driven through the shipped binary.
//!
//! One daemon serves every node it hosts, so the TLS handshake names none of them: the SNI is a
//! fixed placeholder, both ends show the daemon's neutral leaf, and the node is proved inside the
//! connection (`ASK` / `PROVE` / `CLAIM`, under the 1-RTT keys). What a tap on the path can read
//! is every datagram's bytes, and — since QUIC's Initial keys are derived from the client's
//! destination connection id, which is on the wire — the **plaintext of every Initial packet**:
//! the ClientHello (SNI, ALPN, transport parameters) and the ServerHello. Nothing else is readable
//! without an endpoint's keys.
//!
//! **The staging — real processes only.** A `vox node` anchor on `127.0.0.1`, and a member's
//! `vox daemon` whose `--anchor` points at a recording UDP proxy in front of it: every datagram of
//! the member's connections to the anchor crosses the proxy and is kept. The member makes a room,
//! and the anchor saying its board serves that room proves the exchange completed (the anchor took
//! the member's records only from a connection whose `CLAIM` verified).
//!
//! **What is asserted.** The tap decrypts every Initial packet it saw, in both directions
//! (CANNOT MEASURE if it decrypts none, or the plaintext is not a ClientHello and a ServerHello —
//! then it would read nothing and pass). Then, in every raw datagram and in every Initial's
//! plaintext, neither the anchor's nor the member's fingerprint appears — as its 32 bytes, an
//! 8-byte prefix, its base-32 text as `vox id` prints it or a 12-character prefix, or hex
//! (`PRODUCT:` otherwise, naming where).
//!
//! **Mutation.** The dialler's SNI set to the pinned node's fingerprint (the one place in the
//! handshake a name fits): red, on the ClientHello.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use world::{args, mkdir, tempdir, vox_once, VoxProc, IDENTITY, VOX};

/// How long the member's records may take to reach the anchor's board.
const BOARD_WITHIN: Duration = Duration::from_secs(90);

/// Which way a datagram crossed the tap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    /// The member (the dialler, QUIC's client) to the anchor.
    Up,
    /// The anchor back to the member.
    Down,
}

type Seen = Arc<Mutex<Vec<(Dir, Vec<u8>)>>>;

/// A recording UDP proxy on 127.0.0.1 in front of `upstream`: one upstream socket per client
/// address, as a NAT would, every datagram kept with its direction.
fn tap(upstream: SocketAddr) -> (SocketAddr, Seen) {
    let front = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind the tap");
    let at = front.local_addr().expect("APPARATUS: the tap's address");
    let seen: Seen = Arc::default();
    let rec = Arc::clone(&seen);
    std::thread::spawn(move || {
        let front = Arc::new(front);
        let mut backs: BTreeMap<SocketAddr, Arc<UdpSocket>> = BTreeMap::new();
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((n, client)) = front.recv_from(&mut buf) else {
                continue;
            };
            let back = backs.entry(client).or_insert_with(|| {
                let b = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind"));
                b.connect(upstream)
                    .expect("APPARATUS: connect the tap upstream");
                let (b2, f2, rec2) = (Arc::clone(&b), Arc::clone(&front), Arc::clone(&rec));
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65_535];
                    while let Ok(n) = b2.recv(&mut buf) {
                        rec2.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((Dir::Down, buf[..n].to_vec()));
                        let _ = f2.send_to(&buf[..n], client);
                    }
                });
                b
            });
            rec.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((Dir::Up, buf[..n].to_vec()));
            let _ = back.send(&buf[..n]);
        }
    });
    (at, seen)
}

// ---- reading QUIC v1 as a passive observer can (RFC 9000 §17, RFC 9001 §5) ----------------------

/// A QUIC variable-length integer at `b[*i..]`, advancing `*i`.
fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let first = *b.get(*i)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*i..*i + len)?;
    let mut v = u64::from(first & 0x3f);
    for x in &bytes[1..] {
        v = (v << 8) | u64::from(*x);
    }
    *i += len;
    Some(v)
}

/// One long-header packet of a datagram.
struct Long<'a> {
    kind: u8,
    dcid: &'a [u8],
    /// The whole packet, header through the end of its payload.
    bytes: &'a [u8],
    /// Where the (protected) packet number starts within `bytes`.
    pn_at: usize,
}

/// The long-header packets coalesced in one datagram; a short-header packet ends it.
fn long_packets(d: &[u8]) -> Vec<Long<'_>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < d.len() && d[at] & 0x80 != 0 {
        let p = &d[at..];
        let parsed = (|| {
            let kind = (p[0] >> 4) & 0x03;
            let mut i = 5usize; // first byte, version
            let dl = usize::from(*p.get(i)?);
            i += 1;
            let dcid = p.get(i..i + dl)?;
            i += dl;
            let sl = usize::from(*p.get(i)?);
            i += 1 + sl;
            if kind == 3 {
                return None; // Retry: no payload to read; ends the walk
            }
            if kind == 0 {
                let tl = usize::try_from(varint(p, &mut i)?).ok()?;
                i += tl;
            }
            let len = usize::try_from(varint(p, &mut i)?).ok()?;
            let end = i.checked_add(len)?;
            Some((
                Long {
                    kind,
                    dcid,
                    bytes: p.get(..end)?,
                    pn_at: i,
                },
                end,
            ))
        })();
        let Some((pkt, end)) = parsed else { break };
        out.push(pkt);
        at += end;
    }
    out
}

/// Every frame's CRYPTO data in a decrypted Initial payload, by offset. Other frames are skipped;
/// one this reader does not know ends the walk.
fn crypto_frames(plain: &[u8], into: &mut BTreeMap<u64, Vec<u8>>) {
    let mut i = 0usize;
    while i < plain.len() {
        let Some(t) = varint(plain, &mut i) else {
            return;
        };
        match t {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                let ok = (|| {
                    varint(plain, &mut i)?;
                    varint(plain, &mut i)?;
                    let ranges = varint(plain, &mut i)?;
                    varint(plain, &mut i)?;
                    for _ in 0..ranges {
                        varint(plain, &mut i)?;
                        varint(plain, &mut i)?;
                    }
                    if t == 0x03 {
                        for _ in 0..3 {
                            varint(plain, &mut i)?;
                        }
                    }
                    Some(())
                })()
                .is_some();
                if !ok {
                    return;
                }
            }
            0x06 => {
                let (Some(off), Some(len)) = (varint(plain, &mut i), varint(plain, &mut i)) else {
                    return;
                };
                let Ok(len) = usize::try_from(len) else {
                    return;
                };
                let Some(data) = plain.get(i..i + len) else {
                    return;
                };
                into.insert(off, data.to_vec());
                i += len;
            }
            0x1c | 0x1d => {
                let parsed = (|| {
                    varint(plain, &mut i)?;
                    if t == 0x1c {
                        varint(plain, &mut i)?;
                    }
                    let rl = usize::try_from(varint(plain, &mut i)?).ok()?;
                    i += rl;
                    Some(())
                })();
                if parsed.is_none() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// What the tap read of the Initial packets: each direction's CRYPTO stream, and each decrypted
/// payload.
struct Initials {
    up_crypto: Vec<u8>,
    down_crypto: Vec<u8>,
    plaintexts: Vec<(Dir, Vec<u8>)>,
    decrypted: usize,
    failed: usize,
}

/// Decrypt every Initial packet in `seen`, with the keys any observer derives from the client's
/// first destination connection id (RFC 9001 §5.2).
fn read_initials(seen: &[(Dir, Vec<u8>)]) -> Initials {
    use rustls::quic::{Keys, Version};
    use rustls::Side;
    let suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
        rustls::SupportedCipherSuite::Tls13(s) => s,
        rustls::SupportedCipherSuite::Tls12(_) => unreachable!("a TLS 1.3 suite"),
    };
    let quic = suite.quic.expect("APPARATUS: the suite has QUIC keys");
    let mut out = Initials {
        up_crypto: Vec::new(),
        down_crypto: Vec::new(),
        plaintexts: Vec::new(),
        decrypted: 0,
        failed: 0,
    };
    let mut keys: Option<Keys> = None;
    let (mut up, mut down) = (BTreeMap::new(), BTreeMap::new());
    for (dir, d) in seen {
        for p in long_packets(d).into_iter().filter(|p| p.kind == 0) {
            if keys.is_none() && *dir == Dir::Up {
                keys = Some(Keys::initial(
                    Version::V1,
                    suite,
                    quic,
                    p.dcid,
                    Side::Client,
                ));
            }
            let Some(k) = keys.as_ref() else { continue };
            let side = if *dir == Dir::Up { &k.local } else { &k.remote };
            let sample_at = p.pn_at + 4;
            let Some(sample) = p.bytes.get(sample_at..sample_at + side.header.sample_len()) else {
                out.failed += 1;
                continue;
            };
            let mut first = p.bytes[0];
            let mut pn = [0u8; 4];
            pn.copy_from_slice(&p.bytes[p.pn_at..p.pn_at + 4]);
            if side
                .header
                .decrypt_in_place(sample, &mut first, &mut pn)
                .is_err()
            {
                out.failed += 1;
                continue;
            }
            let pn_len = usize::from(first & 0x03) + 1;
            let mut header = p.bytes[..p.pn_at].to_vec();
            header[0] = first;
            header.extend_from_slice(&pn[..pn_len]);
            let number = pn[..pn_len]
                .iter()
                .fold(0u64, |a, b| (a << 8) | u64::from(*b));
            let mut payload = p.bytes[p.pn_at + pn_len..].to_vec();
            match side.packet.decrypt_in_place(number, &header, &mut payload) {
                Ok(plain) => {
                    let plain = plain.to_vec();
                    crypto_frames(&plain, if *dir == Dir::Up { &mut up } else { &mut down });
                    out.plaintexts.push((*dir, plain));
                    out.decrypted += 1;
                }
                Err(_) => out.failed += 1,
            }
        }
    }
    let join = |m: BTreeMap<u64, Vec<u8>>| {
        let mut s = Vec::new();
        for (off, data) in m {
            let off = usize::try_from(off).unwrap_or(usize::MAX);
            if off <= s.len() {
                let skip = s.len() - off;
                if skip < data.len() {
                    s.extend_from_slice(&data[skip..]);
                }
            }
        }
        s
    };
    out.up_crypto = join(up);
    out.down_crypto = join(down);
    out
}

// ---- the proof -----------------------------------------------------------------------------------

/// Every form a fingerprint could take on the wire, with its name.
fn forms(who: &str, fp_text: &str) -> Vec<(String, Vec<u8>)> {
    let raw = vox_core::node::link::b32_decode(fp_text, "fingerprint")
        .unwrap_or_else(|e| panic!("PRODUCT (staging): {who}'s fingerprint {fp_text:?}: {e:?}"));
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        (format!("{who}'s fingerprint, 32 bytes"), raw.to_vec()),
        (
            format!("{who}'s fingerprint, first 8 bytes"),
            raw[..8].to_vec(),
        ),
        (
            format!("{who}'s fingerprint as text"),
            fp_text.as_bytes().to_vec(),
        ),
        (
            format!("{who}'s fingerprint as upper-case text"),
            fp_text.to_ascii_uppercase().into_bytes(),
        ),
        (
            format!("{who}'s fingerprint, first 12 characters"),
            fp_text.as_bytes()[..12].to_vec(),
        ),
        (
            format!("{who}'s fingerprint in hex"),
            hex.clone().into_bytes(),
        ),
        (
            format!("{who}'s fingerprint in upper-case hex"),
            hex.to_ascii_uppercase().into_bytes(),
        ),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// `vox …` in `data` with `stdin`.
fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
#[ignore = "real vox processes with production Argon2id; run in release"]
fn a_tap_on_the_handshake_learns_no_node_fingerprint() {
    watchdog::arm();
    let tmp = tempdir();
    let (anchor_dir, member_dir) = (tmp.path().join("anchor"), tmp.path().join("member"));
    for d in [&anchor_dir, &member_dir] {
        mkdir(&d.join("cfg"));
    }

    // The anchor, and the tap in front of it.
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .expect("APPARATUS: the matched line holds the spec")
        .to_owned();
    let (anchor_fp, at) = spec
        .split_once('@')
        .expect("APPARATUS: a spec is fp@address");
    let anchor_fp = anchor_fp.to_owned();
    let port: u16 = at
        .rsplit('/')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("APPARATUS: no port in the anchor's spec {spec:?}"));
    let (tap_at, seen) = tap(SocketAddr::from(([127, 0, 0, 1], port)));
    let tapped_spec = format!("{anchor_fp}@/ip4/127.0.0.1/udp/{}", tap_at.port());

    // The member, through the tap.
    let (ok, member_fp, err) = vox_once(&member_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): the member's `vox id` failed: {err}");
    let member_fp = member_fp.trim().to_owned();
    let pass = tmp.path().join("member.pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: write the passphrase file");
    let _daemon = VoxProc::spawn(
        "member",
        &member_dir,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &tapped_spec,
            "--passphrase-file",
            pass.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let deadline = Instant::now() + BOARD_WITHIN;
    while !vox_once(&member_dir, &args(&["room", "list"])).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the member's daemon never answered `vox room list`"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let (ok, said) = vox_in(
        &member_dir,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "tapped",
        ],
        "the room passphrase\n",
    );
    assert!(ok, "PRODUCT (staging): `vox room create`: {said}");
    let (ok, list, err) = vox_once(&member_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): `vox room list`: {err}");
    let short: String = list
        .lines()
        .find(|l| l.contains("tapped"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the room is not listed: {list}"))
        .chars()
        .take(8)
        .collect();
    // The member's records reached the anchor: the exchange on the tapped path completed.
    let board =
        anchor.expect_staging_within(BOARD_WITHIN, "the anchor's board serving the room", |l| {
            l.contains("vox node: board") && l.contains(&short)
        });
    println!("[proof] the anchor, reached only through the tap: {board}");
    std::thread::sleep(Duration::from_secs(2));

    let seen = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let (up, down) = (
        seen.iter().filter(|(d, _)| *d == Dir::Up).count(),
        seen.iter().filter(|(d, _)| *d == Dir::Down).count(),
    );
    let initials = read_initials(&seen);
    println!(
        "[proof] the tap kept {} datagrams ({up} up, {down} down, {} bytes); it decrypted {} \
         Initial packets ({} would not open); CRYPTO read: {} bytes up, {} down; the ClientHello \
         names {:?}",
        seen.len(),
        seen.iter().map(|(_, d)| d.len()).sum::<usize>(),
        initials.decrypted,
        initials.failed,
        initials.up_crypto.len(),
        initials.down_crypto.len(),
        if contains(&initials.up_crypto, b"vox.invalid") {
            "vox.invalid"
        } else {
            "(not vox.invalid)"
        },
    );
    assert!(
        initials.up_crypto.first() == Some(&0x01) && initials.down_crypto.first() == Some(&0x02),
        "CANNOT MEASURE: the tap did not read a ClientHello and a ServerHello out of the Initial \
         packets (first bytes {:?} / {:?}; {} decrypted, {} failed), so it would find nothing \
         whatever the handshake carried",
        initials.up_crypto.first(),
        initials.down_crypto.first(),
        initials.decrypted,
        initials.failed
    );

    let mut found = Vec::new();
    let mut needles = forms("the anchor", &anchor_fp);
    needles.extend(forms("the member", &member_fp));
    for (what, needle) in &needles {
        for (i, (dir, d)) in seen.iter().enumerate() {
            if contains(d, needle) {
                found.push(format!("{what} in raw datagram {i} ({dir:?})"));
            }
        }
        for (dir, p) in &initials.plaintexts {
            if contains(p, needle) {
                found.push(format!("{what} in an Initial packet's plaintext ({dir:?})"));
            }
        }
    }
    println!(
        "[proof] {} forms of 2 fingerprints searched in {} datagrams and {} Initial plaintexts: \
         {} found",
        needles.len(),
        seen.len(),
        initials.plaintexts.len(),
        found.len()
    );
    assert!(
        found.is_empty(),
        "PRODUCT: a passive observer of the member's connections to the anchor reads a node's \
         fingerprint (ADR-011 requirement 27): {found:#?}"
    );
}
