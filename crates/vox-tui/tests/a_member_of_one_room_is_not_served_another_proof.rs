//! PRD-001 R5 / V29-03 — **a node serves a room's log only to members of that room**, with the
//! node under attack running as the shipped `vox daemon`.
//!
//! The victim is a real `vox daemon` holding two rooms, `alpha` and `bravo`, with posts in each.
//! Xavier is a real `vox` profile that joins `alpha` only, through `vox room join` like a person
//! would. Then xavier's own daemon is stopped and a hostile peer connects **as xavier**: his real
//! identity, read from his profile. It asks the victim for:
//! - room `alpha`, which xavier is a member of. This is the control, and it must be served. A zero
//!   below would mean nothing if this failed.
//! - room `bravo`, which xavier is not a member of. It must be refused, with nothing served.
//!
//! It also checks the other direction. On a fresh connection the victim pushes its open rooms to a
//! peer on its own initiative. It must push `alpha` (the control) and nothing of `bravo`.
//!
//! The hostile peer is `vox-core`'s `raw_sync` client, because the shipped `vox` never asks for a
//! room it doesn't hold, so a person's `vox` cannot make this request. The **node under test** is
//! the shipped binary: that's the side whose behaviour this proves.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod raw_sync;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raw_sync::Ask;
use vox_core::node::paths::Paths;
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

const POSTS: usize = 5;
const ATTEMPTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(90);

/// A one-shot `vox` verb with `stdin` fed in (for room passphrases).
fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
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

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start `vox daemon` for `data`, reading its passphrases from `pass_file`, and wait until it answers.
fn daemon(name: &str, data: &Path, port: u16, spec: &str, pass_file: &Path) -> VoxProc {
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
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// Create room `name` on the running daemon at `data`, post `POSTS` messages, and return its
/// full id (from the invite link) and the link.
fn room_with_posts(data: &Path, name: &str, pass: &str) -> (String, String) {
    let (ok, out, err) = vox_in(data, &["room", "create", "--name", name], pass);
    assert!(ok, "vox room create {name}: {out}{err}");
    let (ok, list, err) = vox_once(data, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let short = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room {name} not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(data, &args(&["room", "invite", &short]));
    assert!(ok, "vox room invite {name}: {err}");
    let link = link.trim().to_owned();
    let full = link
        .strip_prefix("vox://")
        .and_then(|rest| rest.get(..52))
        .unwrap_or_else(|| panic!("an invite link, not {link:?}"))
        .to_owned();
    for n in 0..POSTS {
        let (ok, _, err) = vox_once(
            data,
            &args(&["room", "post", &short, &format!("{name} post {n}")]),
        );
        assert!(ok, "vox room post {name} #{n}: {err}");
    }
    (full, link)
}

#[test]
#[ignore = "real vox processes with production Argon2id and a real join; CI runs it in release"]
fn a_member_of_one_room_is_not_served_another_through_the_shipped_daemon() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, victim_dir, xavier_dir) = (dir("anchor"), dir("victim"), dir("xavier"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    for d in [&victim_dir, &xavier_dir] {
        let (ok, _, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "vox id: {err}");
    }
    let (_, victim_fp, _) = vox_once(&victim_dir, &args(&["id"]));
    let victim_id = vox_tui::tunnel_cli::parse_fingerprint(victim_fp.trim()).expect("victim fp");

    // ---- the victim holds two rooms; xavier joins only alpha, through the real binary --------
    let victim_port = free_port();
    let victim = daemon("victim", &victim_dir, victim_port, &spec, &idpass);
    let (a_full, a_link) = room_with_posts(&victim_dir, "alpha", "alpha passphrase");
    let (b_full, _b_link) = room_with_posts(&victim_dir, "bravo", "bravo passphrase");
    let a = vox_tui::tunnel_cli::parse_fingerprint(&a_full).expect("room alpha id");
    let b = vox_tui::tunnel_cli::parse_fingerprint(&b_full).expect("room bravo id");

    let xavier = daemon("xavier", &xavier_dir, free_port(), &spec, &idpass);
    let (ok, out, err) = vox_in(
        &xavier_dir,
        &["room", "join", &a_link, "--name", "alpha"],
        "alpha passphrase",
    );
    assert!(ok, "xavier joins alpha: {out}{err}");
    let (_, xlist, _) = vox_once(&xavier_dir, &args(&["room", "list"]));
    assert!(
        !xlist.contains("bravo"),
        "xavier must not be a member of bravo: {xlist}"
    );
    // Let the victim record xavier as a member of alpha before anything else happens.
    std::thread::sleep(Duration::from_secs(3));

    // ---- xavier's node is stopped; the victim restarts so the attacker's is a fresh connection
    drop(xavier);
    drop(victim);
    let rooms = tmp.path().join("victim.pass");
    std::fs::write(
        &rooms,
        format!("{IDENTITY}\n{a_full} alpha passphrase\n{b_full} bravo passphrase\n"),
    )
    .unwrap();
    let _victim = daemon("victim", &victim_dir, victim_port, &spec, &rooms);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let xpaths = Paths::resolve("default", Some(&xavier_dir), Some(&xavier_dir.join("cfg")))
            .expect("xavier's paths");
        let endpoint = raw_sync::endpoint_as_member(&xpaths, IDENTITY.as_bytes()).await;
        let conn = Arc::new(
            endpoint
                .connect(
                    format!("127.0.0.1:{victim_port}").parse().unwrap(),
                    victim_id,
                    raw_sync::now(),
                )
                .await
                .expect("xavier's identity connects to the victim"),
        );
        let pushed = raw_sync::answer_victim(Arc::clone(&conn));

        // ---- the control: alpha is served to its member ---------------------------------------
        let mut control = raw_sync::Yield::default();
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            control = raw_sync::ask(&conn, a, 0, Ask::Everything, None).await;
            if control.hello && control.entries >= POSTS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        println!("control: asked for alpha as its member → {control:?}");
        assert!(
            control.hello && control.entries >= POSTS,
            "the CONTROL failed, so a zero below would prove nothing: alpha's member was not \
             served alpha's posts — {control:?}"
        );

        // ---- the attack: bravo, as a member of alpha only --------------------------------------
        let (mut answered, mut leaked) = (0usize, 0usize);
        for attempt in 1..=ATTEMPTS {
            let y = raw_sync::ask(&conn, b, 0, Ask::Everything, None).await;
            println!("attempt {attempt}: asked for bravo as a member of alpha only → {y:?}");
            answered += usize::from(y.hello);
            leaked += y.entries;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        assert_eq!(
            (answered, leaked),
            (0, 0),
            "a member of alpha was served bravo: {leaked} entries over {answered} answered \
             sessions. A node must serve a room's log only to that room's members (PRD-001 R5)"
        );

        // ---- the other direction: the victim's own push reaches alpha, never bravo --------------
        let a_pushed = tokio::time::timeout(TIMEOUT, async {
            loop {
                if pushed
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(c, y)| *c == a && y.hello)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            a_pushed.is_ok(),
            "the push CONTROL failed: the victim never pushed alpha to its member on a fresh \
             connection, so a zero for bravo would prove nothing — {:?}",
            pushed.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = pushed.lock().unwrap().clone();
        let b_sessions = got.iter().filter(|(c, y)| *c == b && y.hello).count();
        let b_entries: usize = got
            .iter()
            .filter(|(c, _)| *c == b)
            .map(|(_, y)| y.entries)
            .sum();
        println!(
            "victim-initiated: {} sessions; bravo {b_sessions} sessions / {b_entries} entries",
            got.len()
        );
        assert_eq!(
            (b_sessions, b_entries),
            (0, 0),
            "the victim pushed bravo to a member of alpha only (PRD-001 R5)"
        );
    });
    drop(anchor);
}
