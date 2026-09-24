//! ADR-017 **M17.3 gate** — `vox up`: a real service reached by its `.vox` name, over a
//! real SOCKS5 connection, with no privilege of any kind.
//!
//! ```text
//! SOCKS5 client ──▶ vox up (127.0.0.1:1080) ──▶ QUIC tunnel ──▶ host ──▶ real echo
//!  (what ssh's         resolves the name from      (ADR-011)      checks   on loopback
//!   ProxyCommand        the room's genesis                       dial:<port>
//!   speaks)
//! ```
//!
//! This is the shape Tor uses, and the shape `ssh` reaches through a `ProxyCommand`. What
//! it proves:
//!
//! - a `.vox` **name** — not an address — is what the client sends, and the proxy resolves
//!   it from the room's genesis alone;
//! - the **port becomes the service tag**, authorized by the host's own reacher set
//!   (ADR-017 decision 3), with no certificate issued to anybody;
//! - the bytes reach a real TCP service on the host's loopback and come back;
//! - a name for a room this machine has not joined is refused *at the proxy*, so nothing is
//!   dialled and no address is learned.
//!
//! **No device, no route, no firewall rule, no port below 1024, no `sudo`.** That is the
//! whole reason this is the primary path.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vox_core::governance::capability::{Capability, CapabilitySet};
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::node::link::vox_hostname;
use vox_core::node::resolver::VoxResolver;
use vox_core::node::up::{self, HostDialer};
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use vox_core::transport::streams::{accept_typed, StreamKind};
use vox_core::tunnel::session::{self, HostService};

const NOW: u64 = 1_800_000_000;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0xFF; 32]).unwrap()
}

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    }
}

/// The node's job in production: hand the proxy a live connection to a member. Here it is
/// the one connection the guest already made.
struct OneConnection {
    host: Digest32,
    conn: Arc<VoxConnection>,
}

impl HostDialer for OneConnection {
    async fn connection(&self, host: &Digest32) -> vox_core::error::Result<Arc<VoxConnection>> {
        if *host == self.host {
            Ok(Arc::clone(&self.conn))
        } else {
            Err(vox_core::error::Error::Unreachable(
                "this harness holds one connection, and not to that host",
            ))
        }
    }
}

/// Greet, then CONNECT to `name:port` — what `ssh`'s `ProxyCommand` does through `nc -X 5`.
async fn socks_connect(stream: &mut TcpStream, name: &str, port: u16) -> u8 {
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(u8::try_from(name.len()).unwrap());
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05);
    let rest = match head[3] {
        0x01 => 6,
        0x04 => 18,
        other => panic!("unexpected ATYP {other}"),
    };
    let mut buf = vec![0u8; rest];
    stream.read_exact(&mut buf).await.unwrap();
    head[1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m17_a_service_is_reached_by_name_through_vox_up() {
    watchdog::arm();
    // ---- the host: a real service, a real service room, a real tunnel server ----
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

    let host_signer = signer(7);
    let port = echo_addr.port();
    // The genesis grants every member `dial:<port>`; nobody is issued a certificate
    // (ADR-017 decision 3, M17.1).
    let genesis = Genesis::create_with_nonce_and_grant(
        &host_signer,
        NOW,
        policy(),
        CapabilitySet::from_iter_caps([Capability::dial(port.to_string())]),
        [0x17; 16],
    )
    .unwrap();
    let channel_id = genesis.channel_id();

    let guest_signer = signer(9);

    let host_ep = VoxEndpoint::bind(&host_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let host_id = host_ep.local_id();
    {
        tokio::spawn(async move {
            while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                let client = conn.peer_id();
                tokio::spawn(async move {
                    while let Ok((kind, send, recv)) = accept_typed(&conn).await {
                        if kind != StreamKind::Tunnel {
                            continue;
                        }
                        tokio::spawn(async move {
                            let _ = session::accept(send, recv, &client, |cid, tag| {
                                (*cid == channel_id && tag == port.to_string()).then_some(
                                    HostService {
                                        endpoint: echo_addr,
                                        // **The host trusted this client**, which is the
                                        // whole authorization (ADR-017 decision 3, M17.7).
                                        // This gate previously supplied only an evaluator
                                        // carrying a genesis service grant and so asserted
                                        // the withdrawn model: joining WAS the
                                        // authorization. `reachers` is the host's own
                                        // decision about an identity, and the evaluator no
                                        // longer decides reach at all.
                                        reachers: Arc::new(tokio::sync::watch::Sender::new(
                                            [client].into_iter().collect(),
                                        )),
                                    },
                                )
                            })
                            .await;
                        });
                    }
                });
            }
        });
    }

    // ---- the guest: joined the room, and `vox up` running ----
    let mut resolver = VoxResolver::new();
    assert!(resolver.insert(&genesis), "a service room has a name");
    let hostname = vox_hostname(&channel_id);
    let room = *resolver
        .resolve(&hostname)
        .expect("resolved from the genesis");
    assert_eq!(room.channel_id, channel_id);
    assert_eq!(
        room.host,
        RootSigner::public_key(&host_signer).fingerprint(),
        "the host is the room's creator"
    );

    let guest_ep = VoxEndpoint::bind(&guest_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = Arc::new(guest_ep.connect(host_addr, host_id, NOW).await.unwrap());

    // Bind once and hand the live listener over (M17.16). This used to bind a probe, read
    // its port, drop it and let `up::serve` re-bind — and then **poll up to 200 times**
    // waiting for the address to become connectable. That polling loop was this gate
    // accommodating a product defect: the address was announced over a window where
    // nothing was listening, and the port was stealable in between. A bound socket accepts
    // into the kernel's backlog from the moment of bind, so there is nothing to wait for
    // and the loop is gone. `service_rehearsal_proof` is what caught it, by connecting
    // once, as a person would.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(up::serve(
        listener,
        Arc::new(resolver),
        Arc::new(OneConnection {
            host: room.host,
            conn,
        }),
    ));

    // ---- the client: exactly what `ssh` does through a ProxyCommand ----
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    assert_eq!(
        socks_connect(&mut client, &hostname, port).await,
        0x00,
        "the proxy accepted the .vox name"
    );
    let msg = b"a real service reached by its .vox name over SOCKS";
    client.write_all(msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut back))
        .await
        .expect("the tunnel carried the bytes")
        .expect("a full read");
    assert_eq!(
        back, msg,
        "the bytes went out over the overlay and came back from a real TCP service"
    );

    // The negative that matters now — an identity the host never decided about is refused —
    // belongs in a proof with real nodes, not here: `service_tag` stopped being an
    // authorization input in M17.7, so this gate's old mutation ("dial with the wrong tag")
    // no longer discriminates, and an in-file substitute would only assert that an empty set
    // is empty. It is M17.7's own gate, with two real identities.

    // ---- and: an unheld room is refused at the proxy ----
    let other = Genesis::create_with_nonce_and_grant(
        &signer(3),
        NOW,
        policy(),
        CapabilitySet::from_iter_caps([Capability::dial("22")]),
        [0x33; 16],
    )
    .unwrap();
    let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
    assert_eq!(
        socks_connect(&mut c2, &vox_hostname(&other.channel_id()), 22).await,
        0x02,
        "a room this machine has not joined never reaches a dial"
    );
}
