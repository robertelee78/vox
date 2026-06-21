//! Manual spike (ADR-013/ADR-015 "verified-actually-working"): real TCP carried
//! through a real Vox QUIC tunnel between two separate OS processes, with the Dial
//! capability enforced by a real ADR-007 evaluator.
//!
//!   spike_tunnel host                  # echo service behind a dark tunnel; prints ADDR/ID
//!   spike_tunnel client <addr> <id>    # forwards a local port through the tunnel, round-trips
//!
//! Proves: a real TCP byte stream traverses a real QUIC tunnel across a process
//! boundary, only after the authenticated peer's `dial:echo` capability is granted.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vox_core::governance::evaluator::Evaluator;
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::tunnel::session;

// The dialer/admin identity is shared as a spike constant so the host can build a
// channel in which the dialer is the admin (and thus holds every Dial capability).
const ADMIN_SEED_A: [u8; 32] = [3u8; 32];
const ADMIN_SEED_B: [u8; 32] = [4u8; 32];

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(d: Digest32) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_id(s: &str) -> Digest32 {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex id");
    }
    out
}

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("host") => host().await,
        Some("client") => client(&args[2], &args[3]).await,
        _ => eprintln!("usage: spike_tunnel host | client <addr> <id-hex>"),
    }
}

async fn host() {
    // A real local echo service — the "dark" target behind the tunnel.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // The channel: the dialer (ADMIN_SEED) is the root admin, so it holds dial:echo.
    let admin = SoftwareRootSigner::from_component_seeds(&ADMIN_SEED_A, &ADMIN_SEED_B).unwrap();
    let genesis = Genesis::create_with_nonce(&admin, now(), policy(), [9u8; 16]).unwrap();
    let evaluator = Evaluator::build(&genesis, &[], now(), |_| None).unwrap();

    let host_signer = SoftwareRootSigner::from_component_seeds(&[1u8; 32], &[2u8; 32]).unwrap();
    let ep = VoxEndpoint::bind(&host_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    println!("ADDR={}", ep.local_addr().unwrap());
    println!("ID={}", hex(ep.local_id()));
    eprintln!("host: tunnel ready (dark echo service), waiting for a client process…");

    let conn = ep.accept(now()).await.unwrap().expect("a connection");
    let client_id = conn.peer_id();
    eprintln!("host: peer AUTHENTICATED as {}", hex(client_id));
    let (send, recv) = conn.accept_stream().await.unwrap();
    // accept() ENFORCES dial:echo for client_id before connecting the echo service.
    match session::accept(send, recv, &client_id, &evaluator, |tag| {
        (tag == "echo").then_some(echo_addr)
    })
    .await
    {
        Ok(()) => eprintln!("host: tunnel closed cleanly"),
        Err(e) => eprintln!("host: tunnel ended: {e}"),
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

async fn client(addr: &str, id_hex: &str) {
    let expected = parse_id(id_hex);
    // The client IS the channel admin → holds dial:echo.
    let signer = SoftwareRootSigner::from_component_seeds(&ADMIN_SEED_A, &ADMIN_SEED_B).unwrap();
    let ep = VoxEndpoint::bind(&signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = ep
        .connect(addr.parse().unwrap(), expected, now())
        .await
        .expect("connect+auth");
    println!("client: CONNECTED to host {}", hex(conn.peer_id()));
    let (send, recv) = conn.open_stream().await.unwrap();

    // A local forwarded port: an app connects here, its bytes splice through the tunnel.
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((app_sock, _)) = local.accept().await {
            let _ = session::dial(send, recv, "echo", app_sock).await;
        }
    });

    // The "application": connect to the local forward, send real bytes, expect echo.
    let mut app = TcpStream::connect(local_addr).await.unwrap();
    let payload = b"real TCP through a real Vox tunnel, across processes";
    app.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    let ok = tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut buf))
        .await
        .is_ok()
        && buf == payload;
    println!("client: ECHO {:?}", String::from_utf8_lossy(&buf));
    println!(
        "client: TUNNEL ROUND-TRIP {}",
        if ok { "OK" } else { "FAIL" }
    );
    std::process::exit(if ok { 0 } else { 1 });
}
