//! A hostile peer for the board-membership proofs (V210-70): a test-side client that speaks
//! the Vox wire protocol to a real `vox` process, with an identity of its own or a real
//! member's.
//!
//! No `vox` command can do what these peers do: publish a genesis for a room it just minted,
//! publish a bundle for a key nobody admitted, or ask a node to carry a circuit to an
//! identity of its own choosing. The attacker is not a person using vox, so it is not a `vox`
//! process; everything it talks to is.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::nat::service::RendezvousClient;
use vox_core::node::circuitstream::CircuitFrame;
use vox_core::transport::framing::{read_frame, write_frame};
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use vox_core::transport::streams::{accept_typed, open_typed, StreamKind};

/// The unix time now, in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A runtime shut down **without waiting** when dropped: a task blocked on a victim that
/// never answers must not hold the test open past its verdict (ADR-018 §6).
pub struct Rt(Option<tokio::runtime::Runtime>);

impl Rt {
    /// A multi-threaded runtime for the hostile peers.
    pub fn new() -> Self {
        Self(Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap(),
        ))
    }
}

impl std::ops::Deref for Rt {
    type Target = tokio::runtime::Runtime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

/// A fresh identity, deterministic from `seed`.
pub fn stranger(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0x5A; 32]).unwrap()
}

/// Connect to the node at `addr`, pinned to its fingerprint `id`, as `signer`. The endpoint
/// is returned too: dropping it ends the connection.
pub async fn connect<S: vox_core::identity::composite::RootSigner>(
    signer: &S,
    addr: std::net::SocketAddr,
    id: Digest32,
) -> (VoxEndpoint, Arc<VoxConnection>) {
    let endpoint = VoxEndpoint::bind(signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = endpoint
        .connect(addr, id, now())
        .await
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: a valid identity was not admitted: {e:?}"));
    (endpoint, Arc::new(conn))
}

/// PUT one record on the node's board. `Ok` is the board's `ACCEPTED`; `Err` carries its
/// refusal (or why the stream failed) as text.
pub async fn put(conn: &VoxConnection, wire: &[u8]) -> Result<(), String> {
    let mut client = RendezvousClient::open(conn)
        .await
        .map_err(|e| format!("rendezvous stream: {e:?}"))?;
    let res = client.put(wire).await.map_err(|e| format!("{e:?}"));
    client.finish();
    res
}

/// What the node said when asked to carry a circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitAnswer {
    /// The node carried it: the circuit is up.
    Opened,
    /// The node answered with a refusal frame.
    Refused(String),
    /// The node would not even take the stream (the stream-kind gate), or it failed.
    Gate(String),
}

/// Ask the node on `conn` to carry a circuit to `target`, and report what it said.
pub async fn ask_circuit(conn: &VoxConnection, target: Digest32) -> CircuitAnswer {
    let (mut send, mut recv) = match open_typed(conn, StreamKind::Circuit).await {
        Ok(pair) => pair,
        Err(e) => return CircuitAnswer::Gate(format!("{e:?}")),
    };
    if let Err(e) = write_frame(&mut send, &CircuitFrame::Open { peer: target }.to_bytes()).await {
        return CircuitAnswer::Gate(format!("{e:?}"));
    }
    let answer =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv, 64 * 1024)).await;
    let out = match answer {
        Err(_) => CircuitAnswer::Gate("no answer in 10s".into()),
        Ok(Err(e)) => CircuitAnswer::Gate(format!("{e:?}")),
        Ok(Ok(None)) => CircuitAnswer::Gate("stream closed".into()),
        Ok(Ok(Some(frame))) => match CircuitFrame::from_bytes(&frame) {
            Ok(CircuitFrame::Opened) => CircuitAnswer::Opened,
            Ok(CircuitFrame::Refused { reason }) => CircuitAnswer::Refused(format!("{reason:?}")),
            Ok(other) => CircuitAnswer::Gate(format!("unexpected {other:?}")),
            Err(e) => CircuitAnswer::Gate(format!("{e:?}")),
        },
    };
    let _ = send.finish();
    out
}

/// Answer every circuit the node offers on `conn` with `OPENED`, as a peer that wants it.
/// Returns how many were offered.
pub fn answer_circuits(rt: &tokio::runtime::Runtime, conn: Arc<VoxConnection>) -> Arc<AtomicUsize> {
    let offered = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&offered);
    rt.spawn(async move {
        let mut held = Vec::new();
        while let Ok((kind, mut send, mut recv)) = accept_typed(&conn).await {
            if kind != StreamKind::Circuit {
                continue;
            }
            if let Ok(Ok(Some(frame))) =
                tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv, 64 * 1024))
                    .await
            {
                if matches!(
                    CircuitFrame::from_bytes(&frame),
                    Ok(CircuitFrame::Incoming { .. })
                ) {
                    count.fetch_add(1, Ordering::SeqCst);
                    let _ = write_frame(&mut send, &CircuitFrame::Opened.to_bytes()).await;
                    held.push((send, recv));
                }
            }
        }
    });
    offered
}

// ---- the real side: `vox` processes, set up the way a person would --------------------------

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// How long any one piece of setup may take before the proof says it cannot measure.
pub const SETUP: Duration = Duration::from_secs(120);

/// Run a one-shot `vox` verb with `stdin` (a room passphrase) and the identity passphrase set.
pub fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
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

/// A free loopback UDP port.
pub fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A profile directory (with its config dir) under `root`.
pub fn profile_dir(root: &Path, name: &str) -> PathBuf {
    let d = root.join(name);
    std::fs::create_dir_all(d.join("cfg")).unwrap();
    d
}

/// Start `vox node` and return it with its `--anchor` spec.
pub fn anchor(data: &Path, listen: &str) -> (VoxProc, String) {
    anchor_with(data, listen, &[])
}

/// [`anchor`] with extra `vox node` arguments (e.g. `--serve trusted`).
pub fn anchor_with(data: &Path, listen: &str, extra: &[&str]) -> (VoxProc, String) {
    let mut argv = vec!["node", "--listen", listen];
    argv.extend_from_slice(extra);
    let mut p = VoxProc::spawn("anchor", data, &args(&argv));
    let spec = p
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .unwrap()
        .to_owned();
    (p, spec)
}

/// The fingerprint `vox id` prints for the profile at `data` (creating the identity).
pub fn fingerprint(data: &Path) -> Digest32 {
    let (ok, out, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox id printed no fingerprint ({e:?}): {out}"))
}

/// Start `vox daemon` on `127.0.0.1:port` for `data` and wait until it answers.
pub fn daemon(name: &str, data: &Path, port: u16, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--anchor",
            spec,
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
    panic!("CANNOT MEASURE: {name}'s daemon never answered `vox room list`");
}

/// Create room `name` on the daemon at `data`; returns its id and an invite link.
pub fn create_room(data: &Path, name: &str, pass: &str) -> (Digest32, String) {
    let (ok, out, err) = vox_in(data, &["room", "create", "--name", name], pass);
    assert!(ok, "CANNOT MEASURE: vox room create {name}: {out}{err}");
    let (ok, list, err) = vox_once(data, &args(&["room", "list"]));
    assert!(ok, "CANNOT MEASURE: vox room list: {err}");
    let short = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("CANNOT MEASURE: room {name} not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(data, &args(&["room", "invite", &short]));
    assert!(ok, "CANNOT MEASURE: vox room invite {name}: {err}");
    let link = link.trim().to_owned();
    let full = link
        .strip_prefix("vox://")
        .and_then(|rest| rest.get(..52))
        .unwrap_or_else(|| panic!("CANNOT MEASURE: an invite link, not {link:?}"));
    let id = vox_core::node::link::b32_decode(full, "room id").expect("a room id");
    (id, link)
}

/// Open a member's profile — its daemon must already be stopped — and return its signer, so a
/// hostile peer can connect **as that member**.
pub fn member_signer(data: &Path) -> Arc<vox_core::atrest::vault::VaultRootSigner> {
    let paths =
        vox_core::node::paths::Paths::resolve("default", Some(data), Some(&data.join("cfg")))
            .expect("the member's paths");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut profile = loop {
        match vox_core::node::profile::Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("CANNOT MEASURE: the member's profile did not open: {e:?}"),
        }
    };
    profile
        .unlock(IDENTITY.as_bytes())
        .expect("CANNOT MEASURE: the member's identity unlocks");
    profile.signer_arc().expect("the member's signer")
}
