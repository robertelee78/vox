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

#[path = "support/ports.rs"]
mod ports;
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
        .expect("APPARATUS: spawn vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write vox's stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` for `data`, reading its passphrases from `pass_file`, and wait until it answers.
fn daemon(name: &str, data: &Path, port: u16, spec: &str, pass_file: &Path) -> VoxProc {
    let mut p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        if matches!(p.child.try_wait(), Ok(Some(_))) && ports::bind_refused(&p.transcript()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // The port taken by another process after it was found free is the staging's race, and the
    // daemon says so when it cannot listen; any other silence is the daemon's.
    let said = p.transcript();
    let side = if said.contains("Address already in use")
        || said.contains("something else already holds that UDP port")
    {
        "APPARATUS: port 127.0.0.1:{port} was taken by another program, so"
    } else {
        "PRODUCT (staging):"
    };
    panic!(
        "{} {name}'s daemon never answered `vox room list` within {TIMEOUT:?}:\n{said}",
        side.replace("{port}", &port.to_string())
    );
}

/// Create room `name` on the running daemon at `data`, post `POSTS` messages, and return its
/// full id (from the invite link), the link, and its short id from `vox room list`.
fn room_with_posts(data: &Path, name: &str, pass: &str) -> (String, String, String) {
    let (ok, out, err) = vox_in(
        data,
        &["room", "create", "--passphrase-file", "-", "--name", name],
        pass,
    );
    assert!(
        ok,
        "PRODUCT (staging): `vox room create {name}` failed: {out}{err}"
    );
    let (ok, list, err) = vox_once(data, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): `vox room list` failed: {err}");
    let short = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): room {name} not listed after its create: {list}")
        })
        .to_owned();
    let (ok, link, err) = vox_once(data, &args(&["room", "invite", &short]));
    assert!(
        ok,
        "PRODUCT (staging): `vox room invite {name}` failed: {err}"
    );
    let link = link.trim().to_owned();
    let full = link
        .strip_prefix("vox://")
        .and_then(|rest| rest.get(..52))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): `vox room invite` printed no invite link: {link:?}")
        })
        .to_owned();
    for n in 0..POSTS {
        let (ok, _, err) = vox_once(
            data,
            &args(&["room", "post", &short, &format!("{name} post {n}")]),
        );
        assert!(
            ok,
            "PRODUCT (staging): `vox room post {name}` #{n} failed: {err}"
        );
    }
    (full, link, short)
}

#[test]
#[ignore = "real vox processes with production Argon2id and a real join; CI runs it in release"]
fn a_member_of_one_room_is_not_served_another_through_the_shipped_daemon() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile directory");
        d
    };
    let (anchor_dir, victim_dir, xavier_dir) = (dir("anchor"), dir("victim"), dir("xavier"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write the passphrase file");

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
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
    }
    let fingerprint = |d: &Path, who: &str| {
        let (_, fp, err) = vox_once(d, &args(&["id"]));
        vox_tui::tunnel_cli::parse_fingerprint(fp.trim()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT (staging): `vox id` printed no fingerprint for {who}: {fp:?} {err} ({e})"
            )
        })
    };
    let victim_id = fingerprint(&victim_dir, "the victim");
    let xavier_id = vox_core::node::link::b32_encode(&fingerprint(&xavier_dir, "xavier"));

    // ---- the victim holds two rooms; xavier joins only alpha, through the real binary --------
    let victim = daemon("victim", &victim_dir, 0, &spec, &idpass);
    // The port the victim chose, from its own report, for its restart below (#410).
    let victim_port =
        ports::loopback_listen(&vox_once(&victim_dir, &args(&["status", "--json"])).1)
            .expect("PRODUCT (staging): the victim reports a loopback listen address")
            .port();
    let (a_full, a_link, a_short) = room_with_posts(&victim_dir, "alpha", "alpha passphrase");
    let (b_full, _b_link, _) = room_with_posts(&victim_dir, "bravo", "bravo passphrase");
    let a = vox_tui::tunnel_cli::parse_fingerprint(&a_full)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): room alpha's id {a_full:?}: {e}"));
    let b = vox_tui::tunnel_cli::parse_fingerprint(&b_full)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): room bravo's id {b_full:?}: {e}"));

    let xavier = daemon("xavier", &xavier_dir, 0, &spec, &idpass);
    let (ok, out, err) = vox_in(
        &xavier_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &a_link,
            "--name",
            "alpha",
        ],
        "alpha passphrase",
    );
    assert!(
        ok,
        "PRODUCT (staging): xavier's join of alpha failed: {out}{err}"
    );
    let (listed, xlist, xerr) = vox_once(&xavier_dir, &args(&["room", "list"]));
    assert!(
        listed && !xlist.contains("bravo"),
        "PRODUCT (staging): xavier must be listed in alpha only: {xlist}{xerr}"
    );
    // The victim must record xavier as a member of alpha before anything else happens: watched in
    // its roster, not hoped for.
    let deadline = Instant::now() + TIMEOUT;
    let roster = loop {
        let (ok, roster, err) = vox_once(&victim_dir, &args(&["room", "roster", &a_short]));
        if ok && roster.lines().any(|l| l.trim() == xavier_id) {
            break roster;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the victim's roster of alpha never named xavier \
             ({xavier_id}) within {TIMEOUT:?}: {roster}{err}"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "staging: the victim's roster of alpha names xavier:\n{}",
        roster.trim()
    );

    // ---- xavier's node is stopped; the victim restarts so the attacker's is a fresh connection
    drop(xavier);
    drop(victim);
    let rooms = tmp.path().join("victim.pass");
    std::fs::write(
        &rooms,
        format!("{IDENTITY}\n{a_full} alpha passphrase\n{b_full} bravo passphrase\n"),
    )
    .expect("APPARATUS: write the victim's passphrase file");
    // On the same port, so the attacker reaches the restarted victim: a port taken meanwhile
    // reads as APPARATUS in `daemon`.
    let mut victim = daemon("victim", &victim_dir, victim_port, &spec, &rooms);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: tokio runtime");
    rt.block_on(async {
        let xpaths = Paths::resolve("default", Some(&xavier_dir), Some(&xavier_dir.join("cfg")))
            .expect("APPARATUS: xavier's paths");
        let endpoint = raw_sync::endpoint_as_member(&xpaths, IDENTITY.as_bytes()).await;
        let conn = Arc::new(
            endpoint
                .connect(
                    format!("127.0.0.1:{victim_port}")
                        .parse()
                        .expect("APPARATUS: the victim's address"),
                    victim_id,
                    raw_sync::now(),
                )
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "PRODUCT (staging): xavier's identity could not connect to the victim, so \
                         nothing below is measured: {e}\nvictim:\n{}",
                        victim.transcript()
                    )
                }),
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
            "PRODUCT (staging): the CONTROL failed, so a zero below would prove nothing: alpha's \
             member was not served alpha's posts — {control:?}\nvictim:\n{}",
            victim.transcript()
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
            "PRODUCT: a member of alpha was served bravo: {leaked} entries over {answered} answered \
             sessions. A node must serve a room's log only to that room's members (PRD-001 R5)"
        );

        // ---- the other direction: the victim's own push reaches alpha, never bravo --------------
        let a_pushed = tokio::time::timeout(TIMEOUT, async {
            loop {
                if pushed
                    .lock()
                    .expect("APPARATUS: a lock the proof holds was poisoned")
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
            "PRODUCT (staging): the push CONTROL failed: the victim never pushed alpha to its member \
             on a fresh connection, so a zero for bravo would prove nothing — {:?}\nvictim:\n{}",
            pushed.lock().expect("APPARATUS: a lock the proof holds was poisoned"),
            victim.transcript()
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = pushed.lock().expect("APPARATUS: a lock the proof holds was poisoned").clone();
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
            "PRODUCT: the victim pushed bravo to a member of alpha only (PRD-001 R5)"
        );
    });
    drop(anchor);
}
