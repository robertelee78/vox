//! V210-75 (#266) — **an anchor two rooms share is redialled at the addresses of both**, through
//! the shipped binary.
//!
//! A node keeps a connection to each room's own anchor, and one anchor is often shared by several
//! rooms, each of which recorded its addresses from the invite it was joined with. When the
//! connection goes, the node redials it at the union of what those rooms name. The union was
//! capped at eight addresses, one room's worth, filled room by room: when the first room (in the
//! node's order) already named eight addresses for the anchor — stale ones, from an old invite —
//! a second room's working address was never dialled, and the node lost its anchor for as long
//! as it ran.
//!
//! **The scene.** A real anchor (`vox node`), alice (`vox daemon --anchor` it) with two rooms,
//! and bob (`vox daemon` with **no anchor of his own**), who joins both from invites alice
//! issued, edited as a stale invite would be:
//! - the room that sorts **first** (the order the node walks its rooms in, by room id) names the
//!   anchor at **eight dead ports** only;
//! - the other names it at its one real address.
//!
//! Bob joins the first through alice's own entry in the link (loopback reaches her directly), and
//! the second through the anchor. Then the anchor is stopped (SIGINT) and started again on the
//! same port, so bob's connection to it is gone and only his redial can bring it back.
//!
//! **Asserted:** bob has no anchors file; both joins succeed; within [`BACK_WITHIN`] of the
//! anchor's restart bob says `connected to this anchor` again.
//!
//! **Which side a red is on.** `PRODUCT:` quotes what vox said or did (a join refused, an anchor
//! that would not stop, bob not back in time); a `vox` step of the setup that failed is
//! `PRODUCT (staging):`, quoting it; `APPARATUS:` names a precondition that was not met;
//! `APPARATUS:` names a fault of this proof's own (a process it could not start, a file
//! it could not write, a signal it could not send). Each join is tried **once**: a join turned
//! away is the product's red, not something to retry past. The bound is read against an
//! **apparatus clock** on the same timeline — how long this machine takes to start
//! `/usr/bin/true` (not vox, so a slow vox reads as the product's), and the poll's slowest turn — and a bound missed while that was over
//! [`APPARATUS_BUDGET`] is APPARATUS (runner stalled).
//!
//! **Mutation that must turn it red:** the union filled room by room and cut at eight
//! (`kept_anchors` in `actor.rs`, candidate 2): the first room's eight dead ports are all bob
//! redials, and he never reaches the anchor again.
//!
//! The window that walks a union larger than one dial (`ANCHOR_DIAL_CANDIDATES`, 32 addresses,
//! five rooms of eight distinct stale addresses each) rests on review.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";
const ROOM_PASS: &str = "a room passphrase\n";
/// Eight: the most addresses one room may name for an anchor (`MAX_ENDPOINTS`).
const DEAD_PORTS: [u16; 8] = [9, 10, 11, 12, 13, 14, 15, 16];
/// How soon after the anchor is back bob must be connected to it again: a tick, the loss, a
/// dial whose candidates start 250 ms apart, and QUIC's Initial retransmits at 1, 2 and 4 s.
const BACK_WITHIN: Duration = Duration::from_secs(20);
/// How long to keep looking after that, so a red says how late (or never) it came back.
const PATIENCE: Duration = Duration::from_secs(60);
/// What a node says when a dial of its anchor lands.
const CONNECTED: &str = "connected to this anchor";
/// The most the apparatus may take, on the same timeline as the bound, for a missed bound to be
/// the product's: starting a `vox` that does nothing, or one poll turn past its sleep.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `vox` on one profile, optionally with something on its stdin (`room create`/`join` want the
/// room passphrase).
fn vox(dir: &Path, args: &[&str], input: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir.join("data"))
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox {args:?}: {e}"));
    if let Some(text) = input {
        let mut pipe = child
            .stdin
            .take()
            .expect("APPARATUS: vox was started without a stdin pipe");
        pipe.write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox {args:?}'s stdin: {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A `vox node` anchor on `127.0.0.1:<port>` (0: any), its output in files under `dir`.
fn anchor(dir: &Path, port: u16, tag: &str) -> Proc {
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: cannot make the anchor's profile");
    let file = |name: String| {
        std::fs::File::create(dir.join(&name))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot create {name}: {e}"))
    };
    Proc(
        Command::new(VOX)
            .args(["node", "--listen", &format!("127.0.0.1:{port}")])
            .env("VOX_DATA_DIR", dir.join("data"))
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            // To files, never a pipe nobody reads: a failed status print takes a node down.
            .stdout(Stdio::from(file(format!("{tag}.out"))))
            .stderr(Stdio::from(file(format!("{tag}.err"))))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox node: {e}")),
    )
}

/// A `vox daemon` on `dir`, unlocked through its stdin, answering on its socket.
fn daemon(dir: &Path, extra: &[&str]) -> (Proc, PathBuf) {
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: cannot make the daemon's profile");
    let err = dir.join("daemon.err");
    let mut argv = vec!["daemon", "--listen", "127.0.0.1:0"];
    argv.extend_from_slice(extra);
    let mut child = Command::new(VOX)
        .args(&argv)
        .env("VOX_DATA_DIR", dir.join("data"))
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap_or_else(
            |e| panic!("APPARATUS: cannot create {}: {e}", err.display()),
        )))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox daemon: {e}"));
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS: the daemon was started without a stdin pipe");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the daemon's passphrase: {e}"));
    drop(pipe);
    let proc = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !vox(dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the daemon on {} never answered `vox room list` within 90 s; its stderr: \
             {:?}",
            dir.display(),
            std::fs::read_to_string(&err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    (proc, err)
}

/// The 12-character room ids `vox room list` prints.
fn room_ids(dir: &Path) -> Vec<String> {
    let (_, out, _) = vox(dir, &["room", "list"], None);
    out.split_whitespace()
        .filter(|w| w.len() == 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .collect()
}

/// A room id's place in the node's own order: the id is the leading base32 of the room's
/// digest, and a node walks its rooms by digest, so the values of the letters compare as the
/// digests do (`a` is 0, `7` is 31).
fn order_key(id: &str) -> Vec<usize> {
    const B32: &str = "abcdefghijklmnopqrstuvwxyz234567";
    id.chars()
        .map(|c| {
            B32.find(c).unwrap_or_else(|| {
                panic!("PRODUCT: `vox room list` printed a room id {id:?} that is not base32")
            })
        })
        .collect()
}

/// `link` with the anchor `anchor_id`'s addresses (the `b=` entries after its `a=`) replaced by
/// `addrs`; every other entry, alice's own included, kept.
fn with_anchor_at(link: &str, anchor_id: &str, addrs: &[String]) -> String {
    let (head, query) = link.split_once('?').unwrap_or_else(|| {
        panic!("PRODUCT: the invite link `vox room invite` printed has no query: {link:?}")
    });
    let mut out = Vec::new();
    let mut in_anchor = false;
    for part in query.split('&') {
        if let Some(id) = part.strip_prefix("a=") {
            in_anchor = id == anchor_id;
            out.push(part.to_owned());
            if in_anchor {
                out.extend(addrs.iter().map(|a| format!("b={a}")));
            }
            continue;
        }
        if part.starts_with("b=") && in_anchor {
            continue;
        }
        if !part.starts_with("b=") {
            in_anchor = false;
        }
        out.push(part.to_owned());
    }
    format!("{head}?{}", out.join("&"))
}

/// The `connected to this anchor` notes bob's daemon has printed about `anchor`.
fn connected_notes(err: &Path, anchor: &str) -> usize {
    std::fs::read_to_string(err)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(&anchor[..12]) && l.contains(CONNECTED))
        .count()
}

/// One `vox room join`, as a person runs it: once. A join turned away is the product's answer.
fn join(dir: &Path, link: &str, name: &str) -> (bool, String) {
    let (ok, out, err) = vox(
        dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link,
            "--name",
            name,
        ],
        Some(ROOM_PASS),
    );
    (ok, format!("{}{}", out.trim(), err.trim()))
}

/// The apparatus clock: how long this machine takes, now, to start a process that is **not**
/// vox (`/usr/bin/true`), spawned as vox is. A stalled runner stalls this too; a vox that is slow,
/// even only to start, does not, so it reads as the product's (the #332 trap).
fn apparatus_spawn() -> Duration {
    let t = Instant::now();
    let ok = std::process::Command::new("/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn /usr/bin/true for the apparatus clock: {e}"))
        .success();
    assert!(
        ok,
        "APPARATUS: /usr/bin/true failed, so the apparatus clock cannot be read"
    );
    t.elapsed()
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_shared_anchor_is_redialled_at_every_rooms_address() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, alice_dir, bob_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("alice"),
        tmp.path().join("bob"),
    );

    // ---- the anchor, and its spec as it writes it -----------------------------------------------
    let mut the_anchor = anchor(&anchor_dir, 0, "anchor");
    let deadline = Instant::now() + Duration::from_secs(60);
    let spec = loop {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: `vox node` never wrote its spec to its anchors file within 60 s: {:?}",
            std::fs::read_to_string(anchor_dir.join("anchor.err")).unwrap_or_default()
        );
        if let Some(line) = std::fs::read_to_string(anchor_dir.join("cfg").join("anchors"))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .find(|l| l.contains("127.0.0.1") && l.contains('@'))
        {
            break line.to_owned();
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let (anchor_id, real_addr) = spec
        .split_once('@')
        .unwrap_or_else(|| panic!("PRODUCT: the anchor wrote a spec with no `@`: {spec:?}"));
    let (anchor_id, real_addr) = (anchor_id.to_owned(), real_addr.to_owned());
    let port: u16 = real_addr
        .rsplit('/')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: the anchor wrote a spec with no port: {spec:?}"));

    // ---- alice, with two rooms that name the anchor ---------------------------------------------
    for d in [&alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", d.display()));
    }
    let (ok, alice_fp, err) = vox(&alice_dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): alice's vox id: {err}");
    let (ok, bob_fp, err) = vox(&bob_dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): bob's vox id: {err}");
    let (alice_fp, bob_fp) = (alice_fp.trim().to_owned(), bob_fp.trim().to_owned());
    let (_alice, alice_err) = daemon(&alice_dir, &["--anchor", &spec]);
    let mut rooms = Vec::new();
    for name in ["one", "two"] {
        let (ok, _, err) = vox(
            &alice_dir,
            &["room", "create", "--passphrase-file", "-", "--name", name],
            Some(ROOM_PASS),
        );
        assert!(ok, "PRODUCT (staging): alice's room create: {err}");
        let id = room_ids(&alice_dir)
            .into_iter()
            .find(|id| !rooms.contains(id))
            .unwrap_or_else(|| {
                panic!("PRODUCT: `vox room list` does not show the room {name} alice just created")
            });
        rooms.push(id);
    }
    rooms.sort_by_key(|id| order_key(id));
    let (first, second) = (rooms[0].clone(), rooms[1].clone());
    // Each invite, once it names the anchor at its real address (alice has reached it).
    let invite = |room: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (_, out, _) = vox(&alice_dir, &["room", "invite", room], None);
            let out = out.trim().to_owned();
            if out.contains(&format!("a={anchor_id}")) && out.contains(&real_addr) {
                break out;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): alice's invite for {room} never named the anchor at {real_addr}: \
                 {out:?}\n{}",
                std::fs::read_to_string(&alice_err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    };
    let dead: Vec<String> = DEAD_PORTS
        .iter()
        .map(|p| format!("/ip4/127.0.0.1/udp/{p}"))
        .collect();
    let stale_link = with_anchor_at(&invite(&first), &anchor_id, &dead);
    let good_link = with_anchor_at(
        &invite(&second),
        &anchor_id,
        std::slice::from_ref(&real_addr),
    );
    assert!(
        dead.iter().all(|a| stale_link.contains(a)) && !stale_link.contains(&real_addr),
        "APPARATUS: the stale link does not name the anchor at the eight dead ports only: \
         {stale_link}"
    );
    println!(
        "[proof] rooms in the node's order: {first} (anchor at {} dead ports), {second} (anchor \
         at {real_addr})",
        dead.len()
    );

    // ---- bob, with no anchor of his own, joins both -----------------------------------------------
    assert!(
        !bob_dir.join("cfg").join("anchors").exists(),
        "PRODUCT (staging): bob has an anchors file, so the anchor would be configured"
    );
    let (_bob, bob_err) = daemon(&bob_dir, &[]);
    let (ok, _, err) = vox(
        &alice_dir,
        &["trust", "add", &bob_fp, "--name", "bob"],
        None,
    );
    assert!(ok, "PRODUCT (staging): alice trusts bob: {err}");
    let (ok, _, err) = vox(
        &bob_dir,
        &["trust", "add", &alice_fp, "--name", "alice"],
        None,
    );
    assert!(ok, "PRODUCT (staging): bob trusts alice: {err}");
    for (link, name) in [(&stale_link, "one"), (&good_link, "two")] {
        let (joined, said) = join(&bob_dir, link, name);
        println!("[proof] bob joined {name}: {joined}");
        assert!(
            joined,
            "PRODUCT: bob's `vox room join` of {name} was refused: {said}\nbob's daemon: {}",
            std::fs::read_to_string(&bob_err).unwrap_or_default()
        );
    }
    let held = room_ids(&bob_dir);
    assert!(
        held.contains(&first) && held.contains(&second),
        "PRODUCT: bob joined both rooms and `vox room list` does not show both: {held:?}"
    );
    // The second join reached the anchor itself (its board), so bob holds a connection to it
    // now, filed by the join rather than by an anchor dial; the restart takes it away.
    std::thread::sleep(Duration::from_secs(3));
    let before = connected_notes(&bob_err, &anchor_id);

    // ---- the anchor goes, and comes back on the same port ---------------------------------------
    // SIGINT, as a person stops it: it closes its connections, so bob learns at once that his
    // is gone. (Killed outright, he would learn it only from the silence, 30 s later.)
    let sent = Command::new("kill")
        .args(["-INT", &the_anchor.0.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "APPARATUS: SIGINT could not be sent to the anchor");
    let stopping = Instant::now();
    while the_anchor.0.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "PRODUCT: the anchor (`vox node`) did not stop within 10 s of SIGINT: {:?}",
            std::fs::read_to_string(anchor_dir.join("anchor.err")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(the_anchor);
    let restarted = Instant::now();
    the_anchor = anchor(&anchor_dir, port, "anchor-again");
    // Each line bob says after the restart, with when, so a late or missing redial shows its
    // dials and their failures in order.
    let mut shown = std::fs::read_to_string(&bob_err)
        .unwrap_or_default()
        .lines()
        .count();
    let (mut turn, mut slowest_turn) = (Instant::now(), Duration::ZERO);
    let back = loop {
        slowest_turn = slowest_turn.max(turn.elapsed().saturating_sub(Duration::from_millis(200)));
        turn = Instant::now();
        let text = std::fs::read_to_string(&bob_err).unwrap_or_default();
        for line in text.lines().skip(shown) {
            let cut: String = line.chars().take(240).collect();
            println!("[bob +{:.1}s] {cut}", restarted.elapsed().as_secs_f64());
        }
        shown = text.lines().count();
        if connected_notes(&bob_err, &anchor_id) > before {
            break Some(restarted.elapsed());
        }
        if restarted.elapsed() > BACK_WITHIN + PATIENCE {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let alive = the_anchor.0.try_wait().ok().flatten().is_none();
    let apparatus = slowest_turn.max(apparatus_spawn());
    let said_it_went = std::fs::read_to_string(&bob_err)
        .unwrap_or_default()
        .contains("the connection to this anchor is gone");
    println!(
        "[proof] after the anchor's restart bob reached it again: {back:?} (bound {BACK_WITHIN:?}, \
         apparatus {apparatus:?}); said it went: {said_it_went}; anchor alive: {alive}"
    );
    if !alive {
        let said = std::fs::read_to_string(anchor_dir.join("anchor-again.err")).unwrap_or_default();
        // Its port is handed back to it; another process taking it meanwhile is this machine's.
        // `vox node` says that as `cannot listen on <addr>: Address already in use (os error N)`
        // (vox-core's `Error::Listen`), or as `cannot listen on <addr>: something else already
        // holds that UDP port`.
        let port_taken = said.contains("cannot listen on")
            && (said.contains("Address already in use")
                || said.contains("something else already holds that UDP port"));
        assert!(
            !port_taken,
            "APPARATUS: the restarted anchor's port was taken meanwhile, so bob had nothing to \
             reach: {said:?}"
        );
        panic!(
            "PRODUCT (staging): the restarted anchor exited, so bob had nothing to reach: {said:?}"
        );
    }
    let back = back.unwrap_or_else(|| {
        panic!(
            "PRODUCT: bob never reached the anchor again within {:?} of its restart. Two rooms name it: \
             {first} at {} dead ports, {second} at {real_addr}; he must redial it at both \
             rooms' addresses, not only the first room's eight.\nbob's stderr:\n{}",
            BACK_WITHIN + PATIENCE,
            dead.len(),
            std::fs::read_to_string(&bob_err).unwrap_or_default()
        )
    });
    if back >= BACK_WITHIN {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "APPARATUS (runner stalled): apparatus took {apparatus:?} (budget {APPARATUS_BUDGET:?}) while bob \
             was back only {back:?} after the anchor's restart"
        );
        panic!(
            "PRODUCT: bob reached the anchor again only {back:?} after its restart, over \
             {BACK_WITHIN:?} (apparatus {apparatus:?})\nbob's stderr:\n{}",
            std::fs::read_to_string(&bob_err).unwrap_or_default()
        );
    }
}
