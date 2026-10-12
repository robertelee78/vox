//! ADR-026 §10 host proofs beside `the_daemon_and_its_nodes_proof.rs` (whose helpers this file
//! copies, as `Account`, `Daemon`, `make_room`, `wait_until`, `stop_pid`): the account's one daemon,
//! every participant the shipped `vox` binary.
//!
//! 1. **D-1, starts at once.** `vox daemon --node <n>` for three nodes, started at the same moment
//!    with no daemon running, end with every node held: one is the daemon, the others hand their
//!    node to it.
//! 2. **Proof 1, nodes handed to a running daemon at once all serve, each as itself, at one
//!    address.** A member on another account joins a room on each, and everyone posts at once.
//! 3. **Proof 7, from a member's side.** A kept node comes back after a daemon restart at the
//!    address its member holds, and they read each other again.

#![allow(clippy::unwrap_used)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "room passphrase for the daemon proof";

/// One account: a data root and a config directory, short enough for a socket path.
struct Account {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    cfg: PathBuf,
}

impl Drop for Account {
    /// A daemon a client started for this account (no child of this proof) is stopped by the pid
    /// in its lock, however the proof ends.
    fn drop(&mut self) {
        layout::reap_daemon(&self.data);
    }
}

impl Account {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("vd")
            // Short, for the socket path: macOS's /private/tmp, else /tmp (Linux).
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .unwrap();
        let data = tmp.path().join("d");
        let cfg = tmp.path().join("c");
        std::fs::create_dir_all(&cfg).unwrap();
        Self {
            _tmp: tmp,
            data,
            cfg,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0");
        for key in ["PATH", "HOME", "TMPDIR"] {
            if let Some(v) = std::env::var_os(key) {
                c.env(key, v);
            }
        }
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_LISTEN", "127.0.0.1:0")
            .env("VOX_IDENTITY_PASSPHRASE", PASS);
        c
    }

    /// Run `vox args` to its end with `stdin`.
    fn run(&self, args: &[&str], stdin: &str) -> (bool, String, String) {
        let mut cmd = self.cmd(args);
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {args:?}: {e}"));
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Make node `name` with an identity, as a person does: `vox id --node <name>`.
    fn make_node(&self, name: &str) -> String {
        let (ok, out, err) = self.run(&["id", "--node", name], "");
        assert!(ok, "APPARATUS: vox id for {name}: {out}{err}");
        out.trim().to_owned()
    }

    fn lock_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.data.join(".daemon/lock"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.data.join(".daemon/log")).unwrap_or_default()
    }
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// SIGTERM to `pid`, a process this proof started, then wait for it to go.
fn stop_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let t0 = Instant::now();
    while alive(pid) && t0.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every `vox daemon` process serving `data`, by its command line.
fn daemons_of(data: &Path) -> Vec<u32> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .unwrap();
    let data = data.to_string_lossy().into_owned();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(" daemon ") && l.contains(&data))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect()
}

fn wait_until(within: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    f()
}

/// A foreground `vox daemon` of `node`, its output in a file.
struct Daemon {
    child: Child,
    out: PathBuf,
}

impl Drop for Daemon {
    /// By its own handle, never by pattern: a proof that fails leaves no daemon behind.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(a: &Account, args: &[&str], env: &[(&str, &str)]) -> Self {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let out = a.data.with_extension(format!("daemon-{n}.out"));
        let f = std::fs::File::create(&out).unwrap();
        let mut c = a.cmd(&[&["daemon"], args].concat());
        for (k, v) in env {
            c.env(k, v);
        }
        let child = c
            .stdin(Stdio::null())
            .stdout(f.try_clone().unwrap())
            .stderr(f)
            .spawn()
            .unwrap();
        eprintln!("[test] vox daemon {args:?} pid {}", child.id());
        Self { child, out }
    }

    fn said(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap_or_default()
    }

    fn expect(&self, what: &str, within: Duration, f: impl Fn(&str) -> bool) {
        assert!(
            wait_until(within, || self.said().lines().any(&f)),
            "PRODUCT (staging): the daemon never said {what}:\n{}",
            self.said()
        );
    }

    fn stop(mut self) -> String {
        stop_pid(self.child.id());
        let _ = self.child.wait();
        self.said()
    }
}

/// A room on `node`, named after it (a node may hold one room of a name), made through the daemon
/// that holds it: its id.
fn make_room(a: &Account, node: &str) -> String {
    let (ok, out, err) = a.run(
        &[
            "room",
            "create",
            "--node",
            node,
            "--passphrase-file",
            "-",
            "--name",
            node,
        ],
        ROOM_PASS,
    );
    assert!(ok, "APPARATUS: room create on {node}: {out}{err}");
    let (ok, list, err) = a.run(&["room", "list", "--node", node], "");
    assert!(ok, "APPARATUS: room list on {node}: {err}");
    list.lines()
        .find_map(|l| l.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| panic!("APPARATUS: no room listed on {node}: {list}"))
}

/// LT-1–6 (#724): the app's saved personal-node choice is apparatus; every grant, join,
/// displayed alias, decision and restart is exercised through the shipped binary. No app runs.
/// Mutant: grant the personal node only Read; the personal-drive assertion must turn PRODUCT red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn local_nodes_trust_each_other_without_a_prompt_and_remember_removals() {
    watchdog::arm();
    let a = Account::new();
    let names = ["personal", "agent-one", "agent-two", "agent-three"];
    let fps: Vec<String> = names.iter().map(|name| a.make_node(name)).collect();
    let elsewhere = Account::new();
    let remote = elsewhere.make_node("remote");
    let start = || {
        let mut daemons = Vec::new();
        for name in names {
            let daemon = Daemon::start(&a, &["--node", name], &[]);
            daemon.expect("its node attached", Duration::from_secs(90), |line| {
                line.starts_with("vox daemon: identity")
                    || line.contains(&format!(
                        "node {name} is held by the daemon already running"
                    ))
            });
            daemons.push(daemon);
        }
        daemons
    };
    let mut daemons = start();
    let person = names[0];
    let manual = |args: &[&str]| {
        let (ok, out, err) = a.run(args, "");
        assert!(
            ok,
            "APPARATUS: staging manual keyring choice {args:?}: {out}{err}"
        );
    };
    // Manual alias/capability and an alias collision must survive automation.
    manual(&[
        "trust",
        "add",
        &fps[2],
        "--name",
        "my-teammate",
        "--drive",
        "--node",
        names[1],
    ]);
    manual(&[
        "trust", "add", &remote, "--name", names[1], "--node", person,
    ]);
    manual(&[
        "trust", "add", &fps[3], "--name", names[3], "--node", names[2],
    ]);
    manual(&["trust", "remove", &fps[3], "--node", names[2]]);

    let room = make_room(&a, person);
    let (ok, link, err) = a.run(&["room", "link", &room, "--node", person], "");
    assert!(ok, "APPARATUS: personal node's invite: {err}");
    let link = link
        .lines()
        .find(|line| line.starts_with("vox://"))
        .expect("APPARATUS: the personal node printed a room link");
    let join = |node: &str| {
        let (ok, out, err) = a.run(
            &[
                "room",
                "join",
                link,
                "--node",
                node,
                "--passphrase-file",
                "-",
            ],
            ROOM_PASS,
        );
        assert!(ok, "PRODUCT: local node {node} could not join: {out}{err}");
        assert!(
            !out.contains("Your name for") && !err.contains("Your name for"),
            "PRODUCT: a known local node asked for its name: {out}{err}"
        );
    };
    join(names[1]);
    join(names[2]);

    let ring = |node: &str| {
        let (ok, out, err) = a.run(&["trust", "list", "--node", node], "");
        assert!(
            ok,
            "PRODUCT: {node}'s keyring could not be read: {out}{err}"
        );
        assert!(
            !out.contains("Your name for") && !err.contains("passphrase:"),
            "PRODUCT: local trust required a prompt: {out}{err}"
        );
        out
    };
    let absent = |node: &str, fp: &str| {
        let shown = ring(node);
        assert!(
            !shown.contains(fp),
            "PRODUCT: {node} unexpectedly trusts {fp}: {shown}"
        );
    };
    let has = |node: &str, fp: &str, alias: &str, drive: bool| {
        ring(node).lines().any(|line| {
            line.contains(fp) && line.contains(alias) && line.contains("read + drive") == drive
        })
    };
    // Joining rooms without any saved personal node must not enable local trust.
    absent(person, &fps[1]);
    absent(names[1], &fps[0]);
    absent(names[2], &fps[1]);
    absent(names[3], &fps[1]);
    // A detached passphrase-protected node is Locked in the app's vocabulary (ADR-031 CW-1).
    let (ok, out, err) = a.run(&["node", "detach", names[3]], "");
    assert!(ok, "APPARATUS: locking the late local node: {out}{err}");

    // Stage exactly the setting Vox.app persists when the person selects their node.
    std::fs::create_dir_all(a.cfg.join("app")).expect("APPARATUS: app choice directory");
    std::fs::write(a.cfg.join("app/node"), format!("{person}\n"))
        .expect("APPARATUS: saved personal-node choice");
    assert!(
        wait_until(Duration::from_secs(45), || {
            has(names[1], &fps[0], person, true) && has(names[2], &fps[0], person, true)
        }),
        "PRODUCT: personal drive was not granted; {} said: {}; {} said: {}; log: {}",
        names[1],
        ring(names[1]),
        names[2],
        ring(names[2]),
        a.log()
    );
    assert!(
        has(names[1], &fps[2], "my-teammate", true),
        "PRODUCT: local trust overwrote a custom alias or stronger manual grant: {}",
        ring(names[1])
    );
    let collision = format!("{}#{}", names[1], &fps[1][..6]);
    assert!(
        has(person, &fps[1], &collision, false),
        "PRODUCT: the known local name did not get the displayed fingerprint suffix: {}",
        ring(person)
    );
    absent(names[2], &fps[3]);
    let (ok, out, err) = a.run(&["trust", "list", "--node", names[3]], "");
    assert!(
        !ok,
        "PRODUCT: local trust unlocked a node by itself: {out}{err}"
    );
    let (ok, out, err) = a.run(
        &["node", "attach", names[3], "--passphrase-file", "-"],
        PASS,
    );
    assert!(
        ok,
        "PRODUCT: the person could not make their local node Ready: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || has(
            names[3], &fps[1], names[1], false
        )),
        "PRODUCT: a formerly Locked node did not receive its local trust when Ready: {}",
        ring(names[3])
    );
    absent(names[3], &fps[2]);
    absent(names[3], &fps[0]); // It reads another local node, but does not share the personal room yet.
    join(names[3]);
    assert!(
        wait_until(Duration::from_secs(30), || has(
            names[3], &fps[0], person, true
        )),
        "PRODUCT: joining the personal room did not grant personal drive: {}",
        ring(names[3])
    );
    // This node has had no manual keyring operation. Its automatic grants must not open the
    // passphrase window, which is a permission the person sees in status.
    let (ok, out, err) = a.run(&["status", "--json", "--node", names[3]], "");
    assert!(
        ok,
        "PRODUCT: could not inspect the node's keyring window: {out}{err}"
    );
    let status: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: status was not JSON: {e}: {out}"));
    assert!(
        status
            .get("keyring_open_secs")
            .is_some_and(serde_json::Value::is_null),
        "PRODUCT: automatic local trust opened the keyring passphrase window: {out}"
    );
    for (i, node) in names.iter().enumerate() {
        for (j, other) in names.iter().enumerate() {
            if i == j || matches!((i, j), (2, 3) | (3, 2)) {
                continue;
            }
            let alias: &str = if (i, j) == (1, 2) {
                "my-teammate"
            } else if (i, j) == (0, 1) {
                &collision
            } else {
                other
            };
            let drive = j == 0 || (i, j) == (1, 2);
            assert!(
                wait_until(Duration::from_secs(30), || has(node, &fps[j], alias, drive)),
                "PRODUCT: {node}'s entry for {other} must say {alias} and drive={drive}: {}",
                ring(node)
            );
        }
        let (ok, out, err) = a.run(&["decisions", "--node", node, "--json"], "");
        assert!(
            ok && out.contains("local trust rule"),
            "PRODUCT: {node}'s decision record omitted automatic local trust: {out}{err}"
        );
    }
    // A public keyring entry is useful only if the nodes can read a real room message.
    let text = "local trust lets us work together";
    let (ok, out, err) = a.run(&["room", "post", &room, text, "--node", names[3]], "");
    assert!(
        ok,
        "PRODUCT: automatically trusted node could not post: {out}{err}"
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            let (ok, out, _) = a.run(&["room", "read", &room, "--node", person], "");
            ok && out.contains(text)
        }),
        "PRODUCT: personal node could not read its automatically trusted local member"
    );

    manual(&["trust", "remove", &fps[3], "--node", names[1]]);
    absent(names[1], &fps[3]);
    // Stop only this proof's daemon, then reopen the same identities, room and keyrings.
    let pid = a.lock_pid().expect("APPARATUS: the scratch daemon pid");
    stop_pid(pid);
    daemons.clear();
    daemons = start();
    assert!(
        wait_until(Duration::from_secs(45), || has(
            names[3], &fps[0], person, true
        )),
        "PRODUCT: personal drive was lost after restart: {}",
        ring(names[3])
    );
    absent(names[1], &fps[3]);
    absent(names[2], &fps[3]);
    absent(names[3], &fps[2]);
    assert!(
        has(names[1], &fps[2], "my-teammate", true),
        "PRODUCT: restart lost the pre-existing custom alias or drive grant: {}",
        ring(names[1])
    );
    manual(&[
        "trust",
        "add",
        &fps[3],
        "--name",
        "back-by-choice",
        "--node",
        names[1],
    ]);
    assert!(
        has(names[1], &fps[3], "back-by-choice", false),
        "PRODUCT: the person could not restore a removed local peer by hand: {}",
        ring(names[1])
    );
    drop(daemons);
}

/// The addresses an room link gives for identity `fp` (its `b=` values after `a=<fp>`).
fn addresses_for(link: &str, fp: &str) -> Vec<String> {
    let Some((_, query)) = link.split_once('?') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut current = "";
    for pair in query.split('&') {
        if let Some(a) = pair.strip_prefix("a=") {
            current = a;
        } else if let Some(b) = pair.strip_prefix("b=") {
            if current == fp {
                out.push(b.to_owned());
            }
        }
    }
    out
}

/// **D-1: `vox daemon`s started at once, naming a node each, end with one daemon holding every
/// node.** Three nodes of one account, each started by its own `vox daemon --node <n>` at the same
/// moment with no daemon running: one takes the lock and becomes the account's daemon; the other
/// two MUST hand their node to it (D-1), not fail because it is not answering yet.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn daemons_started_at_once_hand_their_nodes_to_one() {
    const N: usize = 3;
    watchdog::arm();
    let a = Account::new();
    let names: Vec<String> = (0..N).map(|i| format!("n{i}")).collect();
    for n in &names {
        a.make_node(n);
    }
    let daemons: Vec<Daemon> = std::thread::scope(|s| {
        let hs: Vec<_> = names
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || Daemon::start(a, &["--node", n], &[]))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let held: Vec<bool> = names
        .iter()
        .zip(&daemons)
        .map(|(n, d)| {
            wait_until(Duration::from_secs(90), || {
                d.said().lines().any(|l| {
                    l.starts_with("vox daemon: identity")
                        || l.contains(&format!("node {n} is held by the daemon already running"))
                })
            })
        })
        .collect();
    let said: Vec<String> = daemons.into_iter().map(Daemon::stop).collect();
    eprintln!("[proof] each start held its node: {held:?}");
    assert!(
        held.iter().all(|h| *h),
        "PRODUCT: of {N} `vox daemon --node` started at once, not every one held its node          (D-1: one is the daemon, the others hand their node to it): {held:?}
{}",
        names
            .iter()
            .zip(&said)
            .map(|(n, s)| format!("--- vox daemon --node {n} said:\n{s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// **Proof 1 (ADR-026 §10, C-3, D-3): nodes attached at once all serve, at one address, each as
/// itself.** Three nodes of one account: `n0`'s `vox daemon` is the account's daemon, and `n1` and
/// `n2` are handed to it **at the same moment**, each by its own `vox daemon --node <n>`. Each node
/// makes a room at once; every invite gives the
/// same address for its node. A member on another account joins all three rooms — each join
/// reaching its node through that one ip:port, which must prove it is that node — and all four
/// post at once: the member reads each node's post and each node reads the member's.
///
/// What is reused from this file: `Account`, `Daemon`, `make_room`, `lock_pid`, `daemons_of`.
///
/// Mutation: the shared endpoint answering an `ASK` with **another** registered node's key
/// (`Answering::host` in `transport/quic.rs`): a join to any node but that one is refused, red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn nodes_attached_at_once_all_serve_at_one_address_each_as_itself() {
    const N: usize = 3;
    watchdog::arm();
    let a = Account::new();
    let names: Vec<String> = (0..N).map(|i| format!("n{i}")).collect();
    let fps: Vec<String> = names.iter().map(|n| a.make_node(n)).collect();

    // n0's daemon first; then n1 and n2 handed to it at once.
    let first = Daemon::start(&a, &["--node", "n0"], &[]);
    first.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let rest: Vec<Daemon> = std::thread::scope(|s| {
        let hs: Vec<_> = names[1..]
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || Daemon::start(a, &["--node", n], &[]))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let daemons: Vec<Daemon> = std::iter::once(first).chain(rest).collect();
    for (n, d) in names.iter().zip(&daemons) {
        d.expect(
            &format!("node {n} held (as the daemon or by it)"),
            Duration::from_secs(90),
            |l| {
                l.starts_with("vox daemon: identity")
                    || l.contains(&format!(
                        "node {n} is held by the daemon already running here"
                    ))
            },
        );
    }
    let pid = a.lock_pid().unwrap_or_else(|| {
        panic!(
            "PRODUCT: no daemon holds the account's lock\nlog:\n{}",
            a.log()
        )
    });
    let held: Vec<bool> = names
        .iter()
        .map(|n| a.run(&["room", "list", "--node", n], "").0)
        .collect();
    let serving = daemons_of(&a.data);
    eprintln!("[proof] lock holder {pid}; daemons serving the account {serving:?}; each node answers {held:?}");
    assert!(
        held.iter().all(|h| *h),
        "PRODUCT: not every node attached at once answers: {held:?}"
    );

    // A room on each node, made at once.
    let rooms: Vec<String> = std::thread::scope(|s| {
        let hs: Vec<_> = names
            .iter()
            .map(|n| {
                let a = &a;
                s.spawn(move || make_room(a, n))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let links: Vec<String> = names
        .iter()
        .zip(&rooms)
        .map(|(n, r)| {
            let (ok, out, err) = a.run(&["room", "link", "--node", n, r], "");
            assert!(ok, "APPARATUS: room link on {n}: {out}{err}");
            out.lines()
                .find(|l| l.starts_with("vox://"))
                .unwrap_or_else(|| panic!("APPARATUS: no room link from {n}: {out}"))
                .trim()
                .to_owned()
        })
        .collect();
    let addrs: Vec<Vec<String>> = links
        .iter()
        .zip(&fps)
        .map(|(l, fp)| addresses_for(l, fp))
        .collect();
    eprintln!("[proof] each node's invite gives it at: {addrs:?}");
    let shared: Vec<&String> = addrs[0]
        .iter()
        .filter(|x| addrs.iter().all(|v| v.contains(x)))
        .collect();
    // Asserted last, so a red here still says whether every node served.
    let one_address = !shared.is_empty();

    // The member, on an account of its own.
    let m = Account::new();
    let m_fp = m.make_node("default");
    let mpass = m.data.with_extension("pass");
    std::fs::write(&mpass, format!("{PASS}\n")).unwrap();
    let md = Daemon::start(&m, &["--passphrase-file", mpass.to_str().unwrap()], &[]);
    md.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    for (n, fp) in names.iter().zip(&fps) {
        let (ok, out, err) = a.run(&["trust", "add", "--node", n, &m_fp, "--name", "m"], "");
        assert!(ok, "APPARATUS: {n} trusts the member: {out}{err}");
        let (ok, out, err) = m.run(&["trust", "add", fp, "--name", n], "");
        assert!(ok, "APPARATUS: the member trusts {n}: {out}{err}");
    }
    // Every join at once, through the one address.
    let joined: Vec<(bool, String, String)> = std::thread::scope(|s| {
        let hs: Vec<_> = links
            .iter()
            .map(|link| {
                let m = &m;
                s.spawn(move || m.run(&["room", "join", "--passphrase-file", "-", link], ROOM_PASS))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (n, (ok, out, err)) in names.iter().zip(&joined) {
        assert!(
            *ok,
            "PRODUCT: the member's join of {n}'s room, at the daemon's one address, failed: \
             {out}{err}\nhost log:\n{}\nfirst daemon said:\n{}",
            a.log(),
            daemons[0].said()
        );
    }

    // Everyone posts at once.
    std::thread::scope(|s| {
        for (n, r) in names.iter().zip(&rooms) {
            let (a, m) = (&a, &m);
            s.spawn(move || {
                let _ = a.run(&["room", "post", "--node", n, r, &format!("from-{n}")], "");
            });
            s.spawn(move || {
                let _ = m.run(&["room", "post", r, &format!("to-{n}")], "");
            });
        }
    });
    let mut missing = Vec::new();
    for (n, r) in names.iter().zip(&rooms) {
        let member_read = wait_until(Duration::from_secs(90), || {
            m.run(&["room", "read", r], "")
                .1
                .contains(&format!("from-{n}"))
        });
        let node_read = wait_until(Duration::from_secs(90), || {
            a.run(&["room", "read", "--node", n, r], "")
                .1
                .contains(&format!("to-{n}"))
        });
        eprintln!("[proof] {n}: the member read its post = {member_read}; it read the member's = {node_read}");
        if !member_read {
            missing.push(format!("the member did not read {n}'s post"));
        }
        if !node_read {
            missing.push(format!("{n} did not read the member's post"));
        }
    }
    let said: Vec<String> = daemons.into_iter().map(Daemon::stop).collect();
    md.stop();
    assert!(
        missing.is_empty(),
        "PRODUCT: nodes attached at once on one daemon do not all serve: {missing:?}\n\
         host log:\n{}\ndaemons said:\n{}",
        a.log(),
        said.join("\n---\n")
    );
    assert!(
        one_address,
        "PRODUCT: every node served, but the nodes of one daemon are not at one address (D-3): \
         {addrs:?}"
    );
}

/// **Proof 7, from a member's side (ADR-026 L-4, D-3): a kept node comes back after a daemon
/// restart at the address its members hold, and they reach it there.** A kept node with a room a
/// member on another account joined; the daemon stops and a daemon started in the background
/// attaches the node again. Its invite gives the same address as before the restart, and the
/// member and the node each read what the other posts after it.
///
/// What is reused from this file: `Account`, `Daemon`, `make_room`, `lock_pid`, `stop_pid`, and
/// the keep staging of `a_kept_node_and_its_room_come_back_after_a_restart`.
///
/// Mutation: the daemon binding a new port at each start (`.daemon/port` not read): the address
/// changes, red.
#[test]
#[ignore = "real binaries with production Argon2id; run in release"]
fn a_kept_node_is_reached_again_at_its_address_after_a_restart() {
    watchdog::arm();
    let a = Account::new();
    let fp = a.make_node("default");
    let pass = a.data.with_extension("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let d = Daemon::start(&a, &["--passphrase-file", pass.to_str().unwrap()], &[]);
    d.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    let room = make_room(&a, "default");
    d.stop();
    std::fs::write(&pass, format!("{PASS}\n{ROOM_PASS}\n")).unwrap();
    let d = Daemon::start(
        &a,
        &["--keep", "--passphrase-file", pass.to_str().unwrap()],
        &[],
    );
    d.expect("the room held open", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: holding room")
    });
    let invite = |a: &Account| {
        let (ok, out, err) = a.run(&["room", "link", &room], "");
        assert!(ok, "PRODUCT: room link: {out}{err}");
        out.lines()
            .find(|l| l.starts_with("vox://"))
            .unwrap_or_else(|| panic!("PRODUCT: no room link: {out}"))
            .trim()
            .to_owned()
    };
    let link = invite(&a);
    let before = addresses_for(&link, &fp);

    let m = Account::new();
    let m_fp = m.make_node("default");
    let mpass = m.data.with_extension("pass");
    std::fs::write(&mpass, format!("{PASS}\n")).unwrap();
    let md = Daemon::start(&m, &["--passphrase-file", mpass.to_str().unwrap()], &[]);
    md.expect("its identity", Duration::from_secs(60), |l| {
        l.starts_with("vox daemon: identity")
    });
    assert!(
        a.run(&["trust", "add", &m_fp, "--name", "m"], "").0,
        "APPARATUS: trust m"
    );
    assert!(
        m.run(&["trust", "add", &fp, "--name", "a"], "").0,
        "APPARATUS: trust a"
    );
    let (ok, out, err) = m.run(
        &["room", "join", "--passphrase-file", "-", &link],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT (staging): the member's join: {out}{err}");

    // The restart.
    d.stop();
    let (ok, out, err) = a.run(&["daemon", "--detach"], "");
    assert!(ok, "PRODUCT: vox daemon --detach failed: {out}{err}");
    let pid = a.lock_pid().expect("PRODUCT: no daemon holds the lock");
    let attached = wait_until(Duration::from_secs(60), || {
        a.log().contains("vox daemon: attached kept node default")
    });
    let after = if attached {
        addresses_for(&invite(&a), &fp)
    } else {
        Vec::new()
    };
    eprintln!("[proof] the node's address before the restart {before:?}, after {after:?}");
    let _ = a.run(&["room", "post", &room, "after-the-restart-from-a"], "");
    let _ = m.run(&["room", "post", &room, "after-the-restart-from-m"], "");
    let m_read = wait_until(Duration::from_secs(90), || {
        m.run(&["room", "read", &room], "")
            .1
            .contains("after-the-restart-from-a")
    });
    let a_read = wait_until(Duration::from_secs(90), || {
        a.run(&["room", "read", &room], "")
            .1
            .contains("after-the-restart-from-m")
    });
    let log = a.log();
    stop_pid(pid);
    md.stop();
    assert!(
        attached,
        "PRODUCT: the restart did not attach the kept node\nlog:\n{log}"
    );
    assert!(
        !before.is_empty() && before == after,
        "PRODUCT: the kept node is at another address after the restart (D-3): {before:?} → \
         {after:?}"
    );
    assert!(
        m_read && a_read,
        "PRODUCT: after the restart the member read the node = {m_read}, the node read the \
         member = {a_read}\nlog:\n{log}"
    );
}
