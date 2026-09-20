//! ADR-017 **M17.3b gate** — a real service reached *by name*, through the interface,
//! with nothing configured in the client and no privilege anywhere in the test.
//!
//! The whole datapath, composed:
//!
//! ```text
//! client TCP stack ─┐                                        ┌─ real echo service
//!                   │  paired device (no kernel)             │   on the host's loopback
//!                   ▼                                        │
//!            node::interface::Netstack ── carry ──▶ QUIC ──▶ node::tunnel::serve
//!            (terminates TCP in userspace)         (ADR-011)  (checks `dial:<port>`)
//! ```
//!
//! What it proves that the module test cannot:
//!
//! - the address the client dials is the one the **resolver** derived from the room's
//!   genesis — the name is resolved, not configured;
//! - the port in the packet header becomes the **service tag** of a real tunnel request,
//!   which a real ADR-007 evaluator authorizes against the room's genesis service grant;
//! - the bytes reach a real TCP service on the host's loopback and come back.
//!
//! **No `tun` device, no route, no `sudo`, and no `bind()` on port 22 anywhere.** That is
//! the property the design was chosen for: the port is a header field, so the datapath is
//! provable in a unit test. What remains for ADR-014 (M17.3c) is attaching the same
//! `Netstack` to a real `tun`/`utun` device so the *kernel* is the client instead of a
//! second userspace stack — recorded there as pending real-hardware validation, as the
//! UPnP work was.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use vox_core::governance::capability::{Capability, CapabilitySet};
use vox_core::governance::evaluator::Evaluator;
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::node::interface::Netstack;
use vox_core::node::link::vox_hostname;
use vox_core::node::resolver::VoxResolver;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{accept_typed, StreamKind};
use vox_core::tunnel::session::{self, HostService};

const SOCKET_BUFFER: usize = 64 * 1024;
const NOW: u64 = 1_800_000_000;

type Wire = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Two of these cross-wired carry IP packets between two stacks with no kernel involved.
struct Paired {
    rx: Wire,
    tx: Wire,
}
struct PairRx(Vec<u8>);
struct PairTx(Wire);

impl RxToken for PairRx {
    fn consume<T, F: FnOnce(&[u8]) -> T>(self, f: F) -> T {
        f(&self.0)
    }
}
impl TxToken for PairTx {
    fn consume<T, F: FnOnce(&mut [u8]) -> T>(self, len: usize, f: F) -> T {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.borrow_mut().push_back(buf);
        r
    }
}
impl Device for Paired {
    type RxToken<'a>
        = PairRx
    where
        Self: 'a;
    type TxToken<'a>
        = PairTx
    where
        Self: 'a;
    fn receive(&mut self, _t: SmolInstant) -> Option<(PairRx, PairTx)> {
        let p = self.rx.borrow_mut().pop_front()?;
        Some((PairRx(p), PairTx(Rc::clone(&self.tx))))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<PairTx> {
        Some(PairTx(Rc::clone(&self.tx)))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }
}

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0xFF; 32]).unwrap()
}

#[test]
fn m17_a_service_is_reached_by_name_through_the_interface() {
    // `current_thread`: the netstack loop and the client stack are driven by hand so the
    // test is deterministic, and `smoltcp`'s sockets never cross a thread.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        // ---- the host: a real service, a real room, a real tunnel server ----
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // The room's genesis grants every member `dial:<port>` — nobody is issued a
        // certificate (ADR-017 decision 3, M17.1).
        let host_signer = signer(7);
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
        };
        let port = echo_addr.port();
        let genesis = Genesis::create_with_nonce_and_grant(
            &host_signer,
            NOW,
            policy,
            CapabilitySet::from_iter_caps([Capability::dial(port.to_string())]),
            [0x17; 16],
        )
        .unwrap();
        let channel_id = genesis.channel_id();

        // The guest's identity is a member of the room as far as the host is concerned,
        // which is what the genesis grant is conferred on.
        let guest_signer = signer(9);
        let guest_fp = RootSigner::public_key(&guest_signer).fingerprint();
        let members = [guest_fp].into_iter().collect();
        let authors: std::collections::BTreeMap<_, _> =
            [(guest_fp, RootSigner::public_key(&guest_signer))]
                .into_iter()
                .collect();
        let evaluator = Arc::new(
            Evaluator::build_with_members(
                &genesis,
                &[],
                NOW,
                |id| authors.get(id).cloned(),
                members,
            )
            .unwrap(),
        );

        let host_ep = VoxEndpoint::bind(&host_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
        let host_addr = host_ep.local_addr().unwrap();
        let host_id = host_ep.local_id();
        {
            let evaluator = Arc::clone(&evaluator);
            tokio::spawn(async move {
                while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                    let client = conn.peer_id();
                    let evaluator = Arc::clone(&evaluator);
                    tokio::spawn(async move {
                        while let Ok((kind, send, recv)) = accept_typed(&conn).await {
                            if kind != StreamKind::Tunnel {
                                continue;
                            }
                            let evaluator = Arc::clone(&evaluator);
                            tokio::spawn(async move {
                                let _ = session::accept(send, recv, &client, |cid, tag| {
                                    (*cid == channel_id && tag == port.to_string()).then_some(
                                        HostService {
                                            evaluator,
                                            endpoint: echo_addr,
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

        // ---- the guest: resolve the name, bring up the interface ----
        let mut resolver = VoxResolver::new();
        assert!(resolver.insert(&genesis), "a service room has a name");
        let hostname = vox_hostname(&channel_id);
        let service_addr = resolver
            .resolve(&hostname)
            .expect("the name resolves from the genesis alone");
        // The address is the host's, derived from its key — not configured here.
        assert_eq!(service_addr.octets()[0], 0xFD);
        let room = *resolver.route(&service_addr).expect("and it routes back");
        assert_eq!(room.channel_id, channel_id);

        let guest_ep = VoxEndpoint::bind(&guest_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
        let conn = Arc::new(
            guest_ep
                .connect(host_addr, host_id, NOW)
                .await
                .expect("the guest reaches the host"),
        );

        let a2b: Wire = Rc::new(RefCell::new(VecDeque::new()));
        let b2a: Wire = Rc::new(RefCell::new(VecDeque::new()));
        let stack_dev = Paired {
            rx: Rc::clone(&a2b),
            tx: Rc::clone(&b2a),
        };
        let mut cli_dev = Paired {
            rx: Rc::clone(&b2a),
            tx: Rc::clone(&a2b),
        };
        let (acc_tx, mut acc_rx) = tokio::sync::mpsc::channel(4);
        let netstack = Netstack::new(stack_dev, &[service_addr], acc_tx).unwrap();
        tokio::task::spawn_local(netstack.run());

        // Whatever the interface terminates gets carried to the room's host, with the
        // port as the service tag.
        {
            let conn = Arc::clone(&conn);
            tokio::task::spawn_local(async move {
                while let Some(a) = acc_rx.recv().await {
                    assert_eq!(a.to, service_addr);
                    let conn = Arc::clone(&conn);
                    tokio::task::spawn_local(async move {
                        let _ = vox_core::node::tunnel::carry(
                            &conn,
                            &room.channel_id,
                            a.port,
                            a.stream,
                        )
                        .await;
                    });
                }
            });
        }

        // ---- the client: an ordinary TCP connection to the resolved address ----
        let mut clock = SmolInstant::from_millis(0);
        let cli_ip = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x9999);
        let mut cli_if = Interface::new(Config::new(HardwareAddress::Ip), &mut cli_dev, clock);
        cli_if.update_ip_addrs(|l| {
            l.push(IpCidr::new(IpAddress::Ipv6(cli_ip), 128)).unwrap();
        });
        let mut cli_sockets = SocketSet::new(Vec::new());
        let h = cli_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
        ));
        cli_sockets
            .get_mut::<tcp::Socket>(h)
            .connect(
                cli_if.context(),
                (IpAddress::Ipv6(service_addr), port),
                (IpAddress::Ipv6(cli_ip), 49152),
            )
            .unwrap();

        let msg = b"a real service reached by name through the Vox interface";
        let mut sent = false;
        let mut back = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            clock += smoltcp::time::Duration::from_millis(5);
            cli_if.poll(clock, &mut cli_dev, &mut cli_sockets);
            {
                let c = cli_sockets.get_mut::<tcp::Socket>(h);
                if c.can_send() && !sent {
                    c.send_slice(msg).unwrap();
                    sent = true;
                }
                if c.can_recv() {
                    let _ = c.recv(|d| {
                        back.extend_from_slice(d);
                        (d.len(), ())
                    });
                }
            }
            if back.len() >= msg.len() {
                break;
            }
            // Let the netstack loop and the tunnel tasks run.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        assert_eq!(
            back, msg,
            "the bytes went out over the overlay and came back from a real TCP service"
        );
    });
}

#[test]
fn m17_an_unresolvable_name_never_reaches_a_dial() {
    // The negative half: a name for a room this machine has not joined resolves to
    // nothing, so nothing is dialled and no address is learned. `ssh` reports "could not
    // resolve hostname" — the failure is local, immediate, and cannot be misdirected.
    let mine = {
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
        };
        Genesis::create_with_nonce_and_grant(
            &signer(1),
            NOW,
            policy,
            CapabilitySet::from_iter_caps([Capability::dial("22")]),
            [0x01; 16],
        )
        .unwrap()
    };
    let theirs = {
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
        };
        Genesis::create_with_nonce_and_grant(
            &signer(2),
            NOW,
            policy,
            CapabilitySet::from_iter_caps([Capability::dial("22")]),
            [0x02; 16],
        )
        .unwrap()
    };
    let mut resolver = VoxResolver::new();
    resolver.insert(&mine);
    assert!(resolver
        .resolve(&vox_hostname(&theirs.channel_id()))
        .is_none());
    // And the interface answers for exactly one address — the room it holds — so a packet
    // for the other room's address would not even be accepted by the stack.
    let addrs: Vec<_> = resolver.addresses().copied().collect();
    assert_eq!(addrs.len(), 1);
    assert_eq!(
        addrs[0],
        resolver.resolve(&vox_hostname(&mine.channel_id())).unwrap()
    );
}
