//! ADR-012 N-49–N-52 (#413, #414) — **a move to another network is noticed and acted on at once**,
//! through the shipped `vox`.
//!
//! The work is in `tests/netchange/network_change.py`: a daemon D, which listens on every address
//! and advertises A, and its peer P, which can reach D only at A, share a room. The machine then
//! gains B, routes by it, and loses A, as a real interface change the operating system says. Four
//! claims, each printed as a `CLAIM <name> ok|RED` line:
//!
//! - `redial`: with nothing sent, D holds a new connection to P within 3 s (it found the one it
//!   accepted stranded, closed it and dialled P again);
//! - `said`: D's log says the change exactly once, within 1 s of it;
//! - `status`: D's `vox status --json` names the change, and lists B and not A, within 2 s;
//! - `reads`: P reads a post D sends after the change within 5 s of it, not after
//!   `SILENCE_IS_DEATH` (30 s);
//! - `router` (Linux only): before the move, the default route alone changes its next hop, with no
//!   address coming or going, and D says that one change, naming the route, within 1 s (N-50,
//!   N-53). The macOS form does not stage it, since it would change the machine's own default
//!   route.
//!
//! **Linux** is the proof: an unprivileged user and network namespace, whose interfaces the
//! driver changes itself. **macOS** is opt-in heavy (`VOX_PROOF_NETCHANGE_MACOS=1`): the driver
//! makes `lo0` aliases and a host route with `sudo`, which the operator answers, and undoes them.
//!
//! **Mutations that must turn it red:** the event socket never opened (`NetWatch::open` returning
//! its error) → `said`, `status`, `redial` and `reads` red; no redial of the stranded peers
//! (`dial_stranded` doing nothing) → `redial` red; a default route's move ignored
//! (`NetChange::between` comparing the addresses only) → `router` red.
//!
//! A second test, `a_peer_on_loopback_is_not_cut_off_when_the_default_route_moves`, runs on every
//! platform without privilege: it stages a move of the default route through the daemon's own
//! change path (`VOX_TEST_ROUTE_V4_FILE`) and proves a join over loopback survives it.
//!
//! A `vox` step that fails before the move is `PRODUCT (staging):`, after it `PRODUCT:`, each
//! quoting what vox said; the driver's own failures (no `unshare`, a `sudo` step, a crash) are
//! APPARATUS, CANNOT MEASURE, never a pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// How many claims the driver makes here: `router` is staged on Linux only.
const CLAIMS: usize = if cfg!(target_os = "linux") { 5 } else { 4 };

/// Run the driver and judge what it printed.
fn drive() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/netchange/network_change.py"
    );
    let out = Command::new("python3")
        .args([script, VOX])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run python3 {script}: {e}"));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{said}");
    let claims: Vec<&str> = said.lines().filter(|l| l.contains(" CLAIM ")).collect();
    let red: Vec<&&str> = claims.iter().filter(|l| l.contains(" RED:")).collect();
    match out.status.code() {
        Some(0) => assert!(
            claims.len() == CLAIMS && red.is_empty() && said.contains("netchange PASS"),
            "APPARATUS: the driver exited 0 without {CLAIMS} claims ok and a PASS: {said}"
        ),
        // A step before the move failed: the driver's verdict line, not an empty list of claims.
        Some(1) if claims.is_empty() => panic!(
            "{}\n{said}",
            said.lines()
                .find_map(|l| l
                    .strip_prefix("netchange ")
                    .filter(|v| v.starts_with("PRODUCT")))
                .unwrap_or("PRODUCT (staging): the driver ended red before any claim")
        ),
        Some(1) => panic!(
            "PRODUCT: a move to another network must be noticed and acted on at once; red: \
             {red:?}\n{said}"
        ),
        other => panic!("APPARATUS, CANNOT MEASURE: the driver ended {other:?}: {said}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real daemons and a real network change in an unprivileged namespace; run in release"]
fn a_move_to_another_network_is_noticed_and_acted_on() {
    watchdog::arm();
    drive();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "opt-in heavy: changes lo0 aliases and a host route with sudo; the operator runs it"]
fn a_move_to_another_network_is_noticed_and_acted_on() {
    watchdog::arm();
    if std::env::var("VOX_PROOF_NETCHANGE_MACOS").as_deref() != Ok("1") {
        let _ = writeln!(
            std::io::stderr(),
            "HEAVY PROOF NOT RUN: a_move_to_another_network_is_noticed_and_acted_on on macOS \
             changes lo0 aliases and a host route with sudo; the operator runs it with \
             VOX_PROOF_NETCHANGE_MACOS=1 after `sudo -v`. The Linux form is the proof."
        );
        return;
    }
    drive();
}

/// One `vox daemon` on loopback, with the route the machine is staged to have read from `route`
/// (`VOX_TEST_ROUTE_V4_FILE`); killed when dropped.
struct Loopback {
    child: Child,
    data: PathBuf,
    err: PathBuf,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-CONT", &self.child.id().to_string()])
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `vox` with `data` as its node, nothing of the person running the proof inherited.
fn vox_at(data: &Path) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"));
    for k in ["TMUX", "TMUX_PANE", "VOX_NODE", "VOX_ROOM", "VOX_PROXY"] {
        cmd.env_remove(k);
    }
    cmd
}

impl Loopback {
    fn start(data: &Path, route: &Path, env: &[(&str, &str)]) -> Self {
        std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: a node directory");
        let pass = data.join("identity.pass");
        std::fs::write(&pass, "identity passphrase").expect("APPARATUS: a passphrase file");
        let out = vox_at(data)
            .args(["id", "--identity-passphrase-file"])
            .arg(&pass)
            .output()
            .expect("APPARATUS: run vox id");
        assert!(
            out.status.success(),
            "PRODUCT (staging): vox id: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = data.join("daemon.err");
        let mut cmd = vox_at(data);
        cmd.args([
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--proxy",
            "127.0.0.1:0",
        ])
        .arg("--passphrase-file")
        .arg(&pass)
        .env("VOX_TEST_ROUTE_V4_FILE", route)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&err).expect("APPARATUS: the daemon's stderr file"),
        ));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("APPARATUS: start vox daemon");
        let d = Self {
            child,
            data: data.to_owned(),
            err,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while !d.vox(&["room", "list"], "").0 {
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): the daemon never answered `vox room list` in 60 s: {}",
                d.said()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        d
    }

    fn vox(&self, args: &[&str], stdin: &str) -> (bool, String) {
        let mut child = vox_at(&self.data)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: run vox");
        child
            .stdin
            .take()
            .expect("APPARATUS: vox's stdin")
            .write_all(stdin.as_bytes())
            .expect("APPARATUS: write vox's stdin");
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

    fn said(&self) -> String {
        std::fs::read_to_string(&self.err).unwrap_or_default()
    }

    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "APPARATUS: kill {sig} the agent's daemon");
    }
}

/// ADR-012 N-51 — **a peer on loopback is not cut off by a move of the machine's default route.**
/// The change handler probes every connection the node accepted and closes one that does not
/// answer within a quarter second, since QUIC lets only the dialling end follow a move. A
/// connection over loopback cannot be stranded by any move, so it is left alone.
///
/// Staged in userspace through the daemon's own change path: alice's default route is read from a
/// file (`VOX_TEST_ROUTE_V4_FILE`), and writing `none` there is the move her daemon hears and acts
/// on. The agent's node is joining alice's room over 127.0.0.1, its puzzle made to take 4 s
/// (`VOX_TEST_SOLVE_AT_LEAST_MS`), and is stopped (SIGSTOP) across the move: a peer busy for a
/// moment, as one solving on a loaded machine is. The join must still get in.
///
/// Then alice stops while a second join's puzzle runs: the joiner must say the member closed the
/// connection during the exchange, not that it did not answer in time.
///
/// **Mutants**: `close_stranded` probing loopback connections too (alice closes the agent's
/// connection as stranded and the join in flight fails); the joiner's `closed_by_peer` never
/// finding a close (the old words).
#[test]
#[ignore = "real daemons and a staged default-route move; run in release with test-knobs"]
fn a_peer_on_loopback_is_not_cut_off_when_the_default_route_moves() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_ROUTE_V4_FILE", "VOX_TEST_SOLVE_AT_LEAST_MS"]);
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let route = tmp.path().join("route");
    std::fs::write(&route, "192.168.1.1").expect("APPARATUS: the staged route");
    let alice = Loopback::start(&tmp.path().join("alice"), &route, &[]);
    let agent = Loopback::start(
        &tmp.path().join("agent"),
        &route,
        &[("VOX_TEST_SOLVE_AT_LEAST_MS", "4000")],
    );
    let (ok, said) = alice.vox(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        "channel passphrase",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {said}");
    let (_, list) = alice.vox(&["room", "list"], "");
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` named no room: {list}"))
        .to_owned();
    let (ok, link) = alice.vox(&["room", "link", &room], "");
    let link = link
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room link` printed no link: {link}"))
        .to_owned();
    assert!(
        ok && link.contains("/ip4/127.0.0.1/"),
        "PRODUCT (staging): the link names alice on loopback: {link}"
    );

    // The join, under way: its puzzle takes 4 s, on a connection alice accepted.
    let joining = std::thread::spawn({
        let data = agent.data.clone();
        move || {
            let mut child = vox_at(&data)
                .args(["room", "join", &link, "--passphrase-file", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("APPARATUS: run vox room join");
            child
                .stdin
                .take()
                .expect("APPARATUS: join's stdin")
                .write_all(b"channel passphrase")
                .expect("APPARATUS: write join's stdin");
            let out = child
                .wait_with_output()
                .expect("APPARATUS: wait for vox room join");
            (
                out.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
            )
        }
    });
    std::thread::sleep(Duration::from_millis(1500));

    // The move, while the agent's node is busy.
    agent.signal("-STOP");
    let moved = Instant::now();
    std::fs::write(&route, "none").expect("APPARATUS: stage the route's move");
    while !alice
        .said()
        .contains("IPv4 default route 192.168.1.1 → none")
    {
        if moved.elapsed() > Duration::from_secs(5) {
            agent.signal("-CONT");
            panic!(
                "APPARATUS: staging not achieved: alice's daemon did not say the staged move \
                 within 5 s: {}",
                alice.said()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Past the probe's patience (a quarter second on loopback), with room to spare.
    std::thread::sleep(Duration::from_millis(1500));
    agent.signal("-CONT");
    let resumed = moved.elapsed();
    let (ok, said) = joining.join().expect("APPARATUS: the join's thread");
    println!(
        "[proof] the agent was stopped {resumed:?} across alice's move; the join said: {:?}\n\
         [proof] alice said: {:?}",
        said.lines().next(),
        alice.said()
    );
    assert!(
        ok && said.contains("joined agents"),
        "PRODUCT: a join over loopback must get in though the machine's default route moved \
         while it was under way (ADR-012 N-51). The join said:\n{said}\nalice's daemon said:\n{}\n\
         the agent's daemon said:\n{}",
        alice.said(),
        agent.said()
    );

    // ---- a member that closes the connection during the exchange is said to have closed it ----
    // alice stops (SIGTERM, a clean stop) while a second joiner's puzzle runs: the joiner must say
    // the member closed the connection, not that it "did not answer the join exchange in time".
    let late = Loopback::start(
        &tmp.path().join("late"),
        &route,
        &[("VOX_TEST_SOLVE_AT_LEAST_MS", "4000")],
    );
    // A room alice alone is in, so no other member can answer the join in her place.
    let (ok, said) = alice.vox(
        &["room", "create", "--passphrase-file", "-", "--name", "solo"],
        "channel passphrase",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {said}");
    let (_, list) = alice.vox(&["room", "list"], "");
    let solo = list
        .lines()
        .find(|l| l.contains("solo"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` named no solo room: {list}"))
        .to_owned();
    let (ok, link) = alice.vox(&["room", "link", &solo], "");
    let link = link
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room link` printed no link: {link}"))
        .to_owned();
    assert!(ok, "PRODUCT (staging): vox room link: {link}");
    let joining = std::thread::spawn({
        let data = late.data.clone();
        move || {
            let mut child = vox_at(&data)
                .args(["room", "join", &link, "--passphrase-file", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("APPARATUS: run vox room join");
            child
                .stdin
                .take()
                .expect("APPARATUS: join's stdin")
                .write_all(b"channel passphrase")
                .expect("APPARATUS: write join's stdin");
            let out = child
                .wait_with_output()
                .expect("APPARATUS: wait for vox room join");
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }
    });
    std::thread::sleep(Duration::from_millis(1500));
    alice.signal("-TERM");
    let said = joining.join().expect("APPARATUS: the join's thread");
    println!("[proof] the join whose member stopped during its exchange said: {said:?}");
    assert!(
        late.said().contains("exchange (incl. solve)") && !said.contains("joined solo"),
        "APPARATUS: staging not achieved: the second join did not reach the exchange before alice \
         stopped: {said}\nits daemon said:\n{}",
        late.said()
    );
    assert!(
        said.contains("closed the connection during the join exchange")
            && !said.contains("did not answer the join exchange in time"),
        "PRODUCT: a member that closed the connection during the join exchange must be said to \
         have closed it, not to have not answered in time:\n{said}\nthe joiner's daemon said:\n{}",
        late.said()
    );
}

/// **A failed read of a node's socket does not leave it deaf.** quinn ends its endpoint on any
/// read error but a reset, and says so only on output nothing reads; the node went on running,
/// unreachable by anyone, in silence (once after a real change of the machine's network: a joiner
/// on loopback was told "no board could be read" on every try). The node's socket now says the
/// failure and reads again.
///
/// Staged with `VOX_TEST_RECV_FAIL_FILE`: while the file exists, alice's next read of her socket
/// fails (the network down) and removes it. The agent's join is what she reads next; it must get in,
/// and the file must be gone (else the failure was never injected: APPARATUS).
///
/// **Mutant**: `MuxSocket::poll_recv` handing the failure up to quinn as before. alice's endpoint
/// ends, she says she stopped taking connections, and the join is not answered.
#[test]
#[ignore = "real daemons and an injected socket read failure; run in release with test-knobs"]
fn a_failed_socket_read_does_not_leave_a_node_deaf() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_RECV_FAIL_FILE"]);
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let route = tmp.path().join("route");
    std::fs::write(&route, "192.168.1.1").expect("APPARATUS: the staged route");
    let fail = tmp.path().join("fail-next-read");
    let fail_env = fail.to_str().expect("APPARATUS: a UTF-8 path").to_owned();
    let alice = Loopback::start(
        &tmp.path().join("alice"),
        &route,
        &[("VOX_TEST_RECV_FAIL_FILE", fail_env.as_str())],
    );
    let agent = Loopback::start(&tmp.path().join("agent"), &route, &[]);
    let (ok, said) = alice.vox(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        "channel passphrase",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {said}");
    let (_, list) = alice.vox(&["room", "list"], "");
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` named no room: {list}"))
        .to_owned();
    let (ok, link) = alice.vox(&["room", "link", &room], "");
    let link = link
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room link` printed no link: {link}"))
        .to_owned();
    assert!(ok, "PRODUCT (staging): vox room link: {link}");

    // alice's next read fails; the join is what she reads next.
    std::fs::write(&fail, "").expect("APPARATUS: arm the read failure");
    let started = Instant::now();
    let (ok, said) = agent.vox(
        &["room", "join", &link, "--passphrase-file", "-"],
        "channel passphrase",
    );
    let took = started.elapsed();
    println!(
        "[proof] the join, {took:?} after alice's read failed, said: {:?}\n[proof] alice said \
         (the failure, and the read that worked after it):\n{}",
        said.lines().next(),
        alice.said()
    );
    assert!(
        !fail.exists(),
        "APPARATUS: staging not achieved: alice never read her socket with the failure armed \
         (the file is still there); the join said:\n{said}"
    );
    assert!(
        ok && said.contains("joined agents"),
        "PRODUCT: a node whose socket failed one read must keep taking connections: the join to \
         alice on loopback said:\n{said}\nalice's daemon said:\n{}",
        alice.said()
    );
}
