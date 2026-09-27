//! A world of real `vox` processes in which **the only path between host and guest is a relay
//! circuit**, made with nothing but the product's own `--listen`: the anchor listens dual-stack on
//! `[::]`, the host on `127.0.0.1` (an IPv4 socket), the guest on `[::1]` (an IPv6 socket bound to
//! `::1`). Each reaches the anchor; neither can send a datagram to the other, so no direct dial
//! and no hole punch connects them.
//!
//! [`Split::None`] is the **control**: host and guest both on `127.0.0.1`, the same anchor, the
//! same verbs. There the pair goes direct, which is what shows the split — and nothing else — is
//! what forces the relay.
//!
//! **Relayed is observed, never assumed**, from two places: the anchor's own report of circuits
//! it carries ([`RelayWorld::anchor_circuits`]), which a proof checks before and after each
//! measurement, and the guest's `still relayed` report of an upgrade that found nothing better
//! ([`RelayWorld::expect_still_relayed`]).
//!
//! Every process is a [`VoxProc`], killed by its own PID and reaped on drop.
//!
//! Included with `#[path]`, next to `world.rs`, whose process harness it uses.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::world::{after_label, args, echo_service, vox_once, VoxProc, IDENTITY};

/// Whether host and guest are split by address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    /// Host on `127.0.0.1`, guest on `[::1]`: the only path is the anchor's circuit.
    Families,
    /// The control: both on `127.0.0.1`, so a direct path exists.
    None,
}

/// A `vox node` anchor listening dual-stack on `[::]`, named in each family.
pub struct Anchor {
    pub proc: VoxProc,
    /// The anchor as a node on an IPv4 socket names it.
    pub v4_spec: String,
    /// The same anchor as a node on an IPv6 socket names it.
    pub v6_spec: String,
}

impl Anchor {
    /// Start an anchor with its data under `dir`.
    pub fn start(dir: &std::path::Path) -> Self {
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let mut anchor = VoxProc::spawn("anchor", dir, &args(&["node", "--listen", "[::]:0"]));
        let spec = anchor
            .expect_line("an --anchor spec", |l| {
                !l.starts_with("! ")
                    && l.trim_start().contains('@')
                    && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
            })
            .trim()
            .to_owned();
        let (anchor_fp, addr) = spec.split_once('@').expect("fp@addr");
        let port: u16 = addr
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("no port in the anchor spec {spec:?}"));
        Self {
            v4_spec: format!("{anchor_fp}@/ip4/127.0.0.1/udp/{port}"),
            v6_spec: format!("{anchor_fp}@/ip6/::1/udp/{port}"),
            proc: anchor,
        }
    }

    /// How many circuits the anchor says it carries, from the latest report it printed. It prints
    /// on change, so this drains its output (waiting `settle` for a line in flight) and reads the
    /// last one.
    pub fn circuits(&mut self, settle: Duration) -> usize {
        let deadline = Instant::now() + settle;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self
                .proc
                .lines
                .recv_timeout(left.min(Duration::from_millis(200)))
            {
                Ok(line) => {
                    eprintln!("[anchor] {line}");
                    self.proc.seen.push(line);
                }
                Err(_) if left.is_zero() => break,
                Err(_) => {}
            }
        }
        self.proc
            .seen
            .iter()
            .rev()
            .find_map(|l| {
                let rest = l.strip_prefix("vox node: ")?;
                let (_, after) = rest.split_once(" peer(s) connected, ")?;
                after.split_whitespace().next()?.parse().ok()
            })
            .unwrap_or(0)
    }

    /// Assert the anchor is carrying a circuit **now** — before or after a measurement. `when`
    /// names the moment, for the failure.
    pub fn assert_relayed(&mut self, when: &str) {
        let n = self.circuits(Duration::from_secs(2));
        assert!(
            n >= 1,
            "NOT RELAYED {when}: the anchor reports {n} circuit(s) carried — this is not measuring \
             a relayed path.\nanchor:\n{}",
            self.proc.transcript()
        );
    }

    /// Assert the pair is **direct** — for a control that must be. The product reaches a peer
    /// relay-first and upgrades behind it (M15.1b): a join can win through the anchor and switch to
    /// the direct path within a round trip, and the circuit it left is *retired*, not closed, for
    /// `RETIRE_GRACE_SECS` (60 s) so nothing in flight on it is cut. The anchor keeps counting that
    /// circuit until then. Counting once, 2 s in, read that retired circuit as a relayed pair: 1 red
    /// in 10 paired runs, on trees with and without #40. A probe of the red showed the circuit gone
    /// 39 s after the check, within the grace of a join-time upgrade.
    ///
    /// So a direct pair is one whose anchor count reaches **0 within the grace plus 15 s**. An
    /// upgrade that only lands on the 60 s retry (`UPGRADE_RETRY`) would keep the circuit for about
    /// 120 s, and a pair that never upgrades keeps it for good: both are still red.
    pub fn assert_direct(&mut self, when: &str) {
        // The grace plus 15 s of margin (status lines, a loaded box), never a literal: a change
        // to the grace must move this gate with it, not silently break or loosen it.
        let within = Duration::from_secs(vox_core::node::net::RETIRE_GRACE_SECS + 15);
        let t0 = Instant::now();
        let mut n = self.circuits(Duration::from_secs(2));
        let at_once = n == 0;
        while n > 0 && t0.elapsed() < within {
            n = self.circuits(Duration::from_secs(1));
        }
        if at_once {
            eprintln!("[relay] {when}: direct at once (no circuit at the anchor)");
        } else if n == 0 {
            eprintln!(
                "[relay] {when}: direct; a retired circuit closed after {:?}",
                t0.elapsed()
            );
        }
        assert_eq!(
            n,
            0,
            "NOT DIRECT {when}: the anchor still reports {n} circuit(s) carried after {within:?}, \
             past a retired circuit's grace.\nanchor:\n{}",
            self.proc.transcript()
        );
    }
}

impl Split {
    /// The `--listen` for the side that moves to IPv6 under the split (the guest).
    pub fn guest_listen(self) -> &'static str {
        match self {
            Split::Families => "[::1]:0",
            Split::None => "127.0.0.1:0",
        }
    }

    /// The anchor spec that side can use.
    pub fn guest_spec(self, anchor: &Anchor) -> &str {
        match self {
            Split::Families => &anchor.v6_spec,
            Split::None => &anchor.v4_spec,
        }
    }
}

pub struct RelayWorld {
    pub split: Split,
    pub tmp: tempfile::TempDir,
    pub anchor: Anchor,
    pub host_dir: PathBuf,
    pub guest_dir: PathBuf,
    pub host: Option<VoxProc>,
    pub fwd: Option<VoxProc>,
    pub host_fp: String,
    pub room: String,
    pub address: String,
    pub passphrase: String,
    pub service: String,
}

impl RelayWorld {
    /// The guest's `--listen` and the anchor spec it can use.
    fn guest_net(&self) -> (&'static str, &str) {
        (
            self.split.guest_listen(),
            self.split.guest_spec(&self.anchor),
        )
    }

    /// See [`Anchor::circuits`].
    pub fn anchor_circuits(&mut self, settle: Duration) -> usize {
        self.anchor.circuits(settle)
    }

    /// See [`Anchor::assert_relayed`].
    pub fn assert_relayed(&mut self, when: &str) {
        self.anchor.assert_relayed(when);
    }

    /// Anchor, and a host serving a loopback echo service with the guest already trusted.
    pub fn new(split: Split) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (anchor_dir, host_dir, guest_dir) = (
            tmp.path().join("anchor"),
            tmp.path().join("host"),
            tmp.path().join("guest"),
        );
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            std::fs::create_dir_all(d.join("cfg")).unwrap();
        }
        let anchor = Anchor::start(&anchor_dir);
        let v4_spec = anchor.v4_spec.clone();

        let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
        assert!(ok, "vox id (guest): {err}");
        let (ok, host_fp, err) = vox_once(&host_dir, &args(&["id"]));
        assert!(ok, "vox id (host): {err}");
        let host_fp = host_fp.trim().to_owned();
        let (ok, out, err) = vox_once(
            &host_dir,
            &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
        );
        assert!(ok, "trust add: {out}\n{err}");

        let service = echo_service().to_string();
        let mut host = VoxProc::spawn(
            "host",
            &host_dir,
            &args(&[
                "serve",
                &service,
                "--anchor",
                &v4_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let room = after_label(
            &host.expect_line("room", |l| l.starts_with("room ")),
            "room",
        );
        let address = after_label(
            &host.expect_line("address", |l| l.starts_with("address ")),
            "address",
        );
        let passphrase = after_label(
            &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
            "passphrase",
        );
        Self {
            split,
            tmp,
            anchor,
            host_dir,
            guest_dir,
            host: Some(host),
            fwd: None,
            host_fp,
            room,
            address,
            passphrase,
            service,
        }
    }

    /// `vox connect` the guest, on `[::1]`. Returns whether it joined, how long it took, and what
    /// it said.
    pub fn join_guest(&self) -> (bool, Duration, String, String) {
        let (listen, spec) = self.guest_net();
        let t0 = Instant::now();
        let (ok, out, err) = vox_once(
            &self.guest_dir,
            &args(&[
                "connect",
                &self.address,
                "--passphrase",
                &self.passphrase,
                "--anchor",
                spec,
                "--listen",
                listen,
            ]),
        );
        (ok, t0.elapsed(), out, err)
    }

    /// Start the guest's `vox forward` to the host's service, on `[::1]`; returns the local
    /// address it bound.
    pub fn forward(&mut self) -> SocketAddr {
        let (listen, spec) = self.guest_net();
        let (listen, spec) = (listen.to_owned(), spec.to_owned());
        let mut fwd = VoxProc::spawn(
            "forward",
            &self.guest_dir,
            &args(&[
                "forward",
                &self.room,
                &self.host_fp,
                &self.service,
                "127.0.0.1:0",
                "--passphrase",
                &self.passphrase,
                "--anchor",
                &spec,
                "--listen",
                &listen,
            ]),
        );
        let line = fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let at = line
            .split_whitespace()
            .nth(1)
            .expect("an address")
            .parse()
            .expect("a socket address");
        self.fwd = Some(fwd);
        at
    }

    /// **The path is a relay, said by the guest.** The forward's upgrade tries a direct dial and
    /// a punch and reports that neither landed. Without this line nothing here is staging a
    /// relayed path, and the caller must not report anything.
    pub fn expect_still_relayed(&mut self) {
        self.fwd.as_mut().expect("a forward").expect_within(
            Duration::from_secs(60),
            "`still relayed` for the host",
            |l| l.starts_with("! vox: still relayed to"),
        );
    }

    /// Crash the host — `SIGKILL` by its PID, reaped, so its QUIC close never leaves — and bring
    /// the same identity and room back as `vox daemon`, still on IPv4. Returns when it crashed and
    /// when the daemon held the room open again.
    pub fn crash_and_restart_host(&mut self) -> (Instant, Instant) {
        let host = self.host.take().expect("a host");
        let pid = host.child.id();
        drop(host);
        let crashed = Instant::now();
        eprintln!("[test] host pid {pid} killed and reaped");
        let pass_file = self.tmp.path().join("daemon-passphrases");
        std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", self.passphrase)).unwrap();
        let mut daemon = VoxProc::spawn(
            "host-daemon",
            &self.host_dir,
            &args(&[
                "daemon",
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--anchor",
                &self.anchor.v4_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let room = self.room.clone();
        daemon.expect_line("the daemon to hold the room open", |l| {
            l.starts_with("vox daemon: holding room") && l.contains(&room)
        });
        let ready = Instant::now();
        self.host = Some(daemon);
        (crashed, ready)
    }
}
