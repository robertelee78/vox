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
//! **Every red here names its side** (V210-106), as in `world.rs`. An anchor count is only ever
//! read from a status line the anchor printed: with none to read, it is `CANNOT MEASURE`, never 0.
//!
//! Included with `#[path]`, next to `world.rs`, whose process harness it uses.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::world::{
    address_in, after_label, args, echo_service, fingerprint, mkdir, room_pass_file, tempdir, utf8,
    vox_once, VoxProc, IDENTITY,
};

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
        mkdir(&dir.join("cfg"));
        let mut anchor = VoxProc::spawn("anchor", dir, &args(&["node", "--listen", "[::]:0"]));
        let spec = anchor
            .expect_line("an --anchor spec", |l| {
                !l.starts_with("! ")
                    && l.trim_start().contains('@')
                    && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
            })
            .trim()
            .to_owned();
        let (anchor_fp, addr) = spec
            .split_once('@')
            .unwrap_or_else(|| panic!("PRODUCT: the anchor's spec {spec:?} is not fp@address"));
        let port: u16 = addr
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("PRODUCT: no port in the anchor's spec {spec:?}"));
        Self {
            v4_spec: format!("{anchor_fp}@/ip4/127.0.0.1/udp/{port}"),
            v6_spec: format!("{anchor_fp}@/ip6/::1/udp/{port}"),
            proc: anchor,
        }
    }

    /// The UDP port this anchor listens on, from its spec.
    pub fn port(&self) -> u16 {
        self.v4_spec
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| {
                panic!(
                    "APPARATUS: no port in this harness's spec {:?}",
                    self.v4_spec
                )
            })
    }

    /// Stop this anchor (by its PID) and start it again from the same `dir` on the same port, so
    /// every spec naming it still does (V210-57's proof of a prompt redial). A new process: a new
    /// endpoint, a new certificate, every connection to the old one gone.
    pub fn restart(&mut self, dir: &std::path::Path) {
        let port: u16 = self
            .v4_spec
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| {
                panic!(
                    "APPARATUS: no port in this harness's spec {:?}",
                    self.v4_spec
                )
            });
        let listen = format!("[::]:{port}");
        // The old one first, by its own handle, so the port is free for the new one. A kill that
        // did not take would leave the port held, and the restart would measure nothing.
        let killed = self.proc.child.kill();
        match self.proc.child.wait() {
            Ok(status) => eprintln!("[relay] the old anchor stopped ({status})"),
            Err(e) => panic!(
                "APPARATUS: the old anchor (pid {}) could not be stopped: kill {killed:?}, wait {e}",
                self.proc.child.id()
            ),
        }
        let before = self.proc.transcript();
        self.proc = VoxProc::spawn("anchor", dir, &args(&["node", "--listen", &listen]));
        self.proc
            .seen
            .extend(before.lines().map(|l| format!("(before the restart) {l}")));
        self.proc
            .expect_line("the restarted anchor's --anchor spec", |l| {
                !l.starts_with("! ") && l.trim_start().contains('@')
            });
    }

    /// How many circuits the anchor says it carries, from the latest report it printed. It prints
    /// on change, so this drains its output (waiting `settle` for a line in flight) and reads the
    /// last one.
    ///
    /// An anchor prints its first report at start-up, so **no report at all** — after waiting up
    /// to [`FIRST_REPORT`] for one — is `CANNOT MEASURE`: the count is unknown, and reading it as 0
    /// would pass every "the pair is direct" check against an anchor that stopped reporting.
    pub fn circuits(&mut self, settle: Duration) -> usize {
        let t0 = Instant::now();
        let deadline = t0 + settle;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                while let Ok(line) = self.proc.lines.try_recv() {
                    eprintln!("[anchor] {line}");
                    self.proc.seen.push(line);
                }
                if let Some(n) = self.last_report() {
                    return n;
                }
                assert!(
                    t0.elapsed() < FIRST_REPORT,
                    "CANNOT MEASURE: the anchor printed no `vox node: … peer(s) connected, … \
                     circuit(s) carried` report in {:?}, so how many circuits it carries is \
                     unknown. It said:\n{}",
                    t0.elapsed(),
                    self.proc.transcript()
                );
            }
            let wait = if left.is_zero() {
                Duration::from_millis(200)
            } else {
                left.min(Duration::from_millis(200))
            };
            if let Ok(line) = self.proc.lines.recv_timeout(wait) {
                eprintln!("[anchor] {line}");
                self.proc.seen.push(line);
            }
        }
    }

    /// The most circuits the anchor has reported carrying at any moment since it started, after
    /// draining what it printed for `settle` (see [`Self::circuits`]). The anchor reports on
    /// change, every 500 ms, and a circuit it carried lasts at least a retired path's 60 s grace,
    /// so a circuit asked of it at any point in a run is in one of these reports (V210-122).
    /// No report at all is `CANNOT MEASURE`, never 0.
    pub fn circuits_ever(&mut self, settle: Duration) -> usize {
        let _ = self.circuits(settle);
        self.proc
            .seen
            .iter()
            .filter_map(|l| {
                let rest = l.strip_prefix("vox node: ")?;
                let (_, after) = rest.split_once(" peer(s) connected, ")?;
                after.split_whitespace().next()?.parse::<usize>().ok()
            })
            .max()
            .unwrap_or_else(|| {
                panic!(
                    "CANNOT MEASURE: the anchor printed no `… circuit(s) carried` report, so how \
                     many circuits it ever carried is unknown. It said:\n{}",
                    self.proc.transcript()
                )
            })
    }

    /// Where the anchor's output stands now, after draining it: pass it to
    /// [`Self::circuits_since`] to read only the reports printed after this moment.
    pub fn mark(&mut self) -> usize {
        let _ = self.proc.transcript();
        self.proc.seen.len()
    }

    /// The most circuits the anchor reported carrying in what it printed after `mark`, after
    /// draining for `settle`. With no report since, the count it last reported (a report is
    /// printed on change only); with none at all, `CANNOT MEASURE`.
    pub fn circuits_since(&mut self, mark: usize, settle: Duration) -> usize {
        let last = self.circuits(settle);
        self.proc.seen[mark.min(self.proc.seen.len())..]
            .iter()
            .filter_map(|l| {
                let rest = l.strip_prefix("vox node: ")?;
                let (_, after) = rest.split_once(" peer(s) connected, ")?;
                after.split_whitespace().next()?.parse::<usize>().ok()
            })
            .max()
            .map_or(last, |m| m.max(last))
    }

    /// The circuit count in the latest status report this anchor printed, if it printed one.
    fn last_report(&self) -> Option<usize> {
        self.proc.seen.iter().rev().find_map(|l| {
            let rest = l.strip_prefix("vox node: ")?;
            let (_, after) = rest.split_once(" peer(s) connected, ")?;
            after.split_whitespace().next()?.parse().ok()
        })
    }

    /// Assert the anchor is carrying a circuit **now** — before or after a measurement. `when`
    /// names the moment, for the failure.
    pub fn assert_relayed(&mut self, when: &str) {
        let n = self.circuits(Duration::from_secs(2));
        assert!(
            n >= 1,
            "CANNOT MEASURE: staging not achieved: NOT RELAYED {when}: the anchor reports {n} \
             circuit(s) carried, so this is not measuring a relayed path.\nanchor:\n{}",
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
        assert!(
            n == 0,
            "PRODUCT: NOT DIRECT {when}: a pair with a direct path still rides the anchor — it \
             reports {n} circuit(s) carried after {within:?}, past a retired circuit's grace.\nanchor:\n{}",
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

/// How long [`Anchor::circuits`] waits for an anchor's first status report before it calls the
/// count unknown. The anchor prints one on its first tick after start-up.
pub const FIRST_REPORT: Duration = Duration::from_secs(10);

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
    /// The host as an `--anchor` spec (`<fingerprint>@<address>`), from the address its room link
    /// gives for it.
    pub fn host_spec(&self) -> Option<String> {
        let query = self.address.split_once('?')?.1;
        let pairs: Vec<&str> = query.split('&').collect();
        pairs.windows(2).find_map(|w| {
            let id = w[0].strip_prefix("a=")?;
            let at = w[1].strip_prefix("b=")?;
            (id == self.host_fp).then(|| format!("{id}@{at}"))
        })
    }

    /// The room passphrase in a file, for `--passphrase-file`: a room passphrase is never
    /// taken from argv or the environment (V210-72).
    pub fn passphrase_file(&self) -> String {
        room_pass_file(self.tmp.path(), &self.passphrase)
    }

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
        Self::new_with_host_env(split, &[])
    }

    /// [`RelayWorld::new`] with extra environment for the host, for the proofs' test-only knobs
    /// (`test_knobs::require` them first).
    pub fn new_with_host_env(split: Split, host_env: &[(&str, &str)]) -> Self {
        let tmp = tempdir();
        let (anchor_dir, host_dir, guest_dir) = (
            tmp.path().join("anchor"),
            tmp.path().join("host"),
            tmp.path().join("guest"),
        );
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            mkdir(&d.join("cfg"));
        }
        let anchor = Anchor::start(&anchor_dir);
        let v4_spec = anchor.v4_spec.clone();

        let guest_fp = fingerprint(&guest_dir, "guest");
        let host_fp = fingerprint(&host_dir, "host");
        let (ok, out, err) = vox_once(
            &host_dir,
            &args(&["trust", "add", &guest_fp, "--name", "the guest"]),
        );
        assert!(
            ok,
            "PRODUCT (staging): the host's `vox trust add` of the guest failed.\nstdout:\n{out}\nstderr:\n{err}"
        );

        let service = echo_service().to_string();
        let mut host = VoxProc::spawn_env(
            "host",
            &host_dir,
            &args(&[
                "serve",
                &format!("{service}={service}"),
                "--anchor",
                &v4_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
            host_env,
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
                "--passphrase-file",
                &self.passphrase_file(),
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
        self.forward_with_anchors(&[])
    }

    /// [`Self::forward`], naming `extra` anchors (`--anchor` specs) beside the world's own.
    pub fn forward_with_anchors(&mut self, extra: &[&str]) -> SocketAddr {
        let spec = self.guest_net().1.to_owned();
        self.spawn_forward(&spec, extra)
    }

    /// [`Self::forward`], naming the anchor by `anchor_spec` instead of the world's own spec — the
    /// same anchor reached another way, such as through a slow port forward.
    pub fn forward_through(&mut self, anchor_spec: &str) -> SocketAddr {
        self.spawn_forward(anchor_spec, &[])
    }

    fn spawn_forward(&mut self, spec: &str, extra: &[&str]) -> SocketAddr {
        let listen = self.guest_net().0;
        let passphrase_file = self.passphrase_file();
        let mut list = vec![
            "forward",
            &self.room,
            &self.host_fp,
            &self.service,
            "127.0.0.1:0",
            "--passphrase-file",
            &passphrase_file,
            "--anchor",
            spec,
            "--listen",
            listen,
        ];
        for a in extra {
            list.push("--anchor");
            list.push(a);
        }
        let mut fwd = VoxProc::spawn("forward", &self.guest_dir, &args(&list));
        let line = fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let at = address_in(&mut fwd, &line, 1);
        self.fwd = Some(fwd);
        at
    }

    /// **The path is a relay, said by the guest.** The forward's upgrade tries a direct dial and
    /// a punch and reports that neither landed. Without this line nothing here is staging a
    /// relayed path, and the caller must not report anything.
    pub fn expect_still_relayed(&mut self) {
        self.fwd
            .as_mut()
            .expect("APPARATUS: the proof asked for `still relayed` before it started a forward")
            .expect_staging_within(
                Duration::from_secs(60),
                "`still relayed` for the host",
                |l| l.starts_with("! vox: still relayed to"),
            );
    }

    /// Crash the host — `SIGKILL` by its PID, reaped, so its QUIC close never leaves — and bring
    /// the same identity and room back as `vox daemon`, still on IPv4. Returns when it crashed and
    /// when the daemon held the room open again.
    pub fn crash_and_restart_host(&mut self) -> (Instant, Instant) {
        let host = self
            .host
            .take()
            .expect("APPARATUS: the proof crashed a host it had not started");
        let pid = host.child.id();
        drop(host);
        let crashed = Instant::now();
        eprintln!("[test] host pid {pid} killed and reaped");
        let pass_file = self.tmp.path().join("daemon-passphrases");
        std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", self.passphrase))
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass_file.display()));
        let mut daemon = VoxProc::spawn(
            "host-daemon",
            &self.host_dir,
            &args(&[
                "daemon",
                "--passphrase-file",
                &utf8(&pass_file),
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
