//! PRD-001 R43 (#93) — **every room that exists keeps its name** after deniable mode is
//! removed, through the shipped binaries: the published v0.2.9 makes the rooms, this build opens
//! them.
//!
//! A room's name *is* its channelID, the SHA-256 of its genesis's canonical bytes: it is what a
//! `.vox` hostname encodes and what every record on the log is filed under. Deniable mode had a
//! slot in those bytes, and its removal keeps the slot (written `0`, anything else refused). A
//! build that wrote it differently would rename every room that exists, and would then fail to
//! open each one, because a room's genesis must hash to the id it is stored under
//! (`node/channel.rs`, "does not hash to").
//!
//! v0.2.9 makes two rooms on one profile, the two kinds of genesis a release wrote:
//! - a chat room (`vox room create`), with an empty service grant;
//! - a service room (`vox serve`), whose genesis carries a `dial:` grant: the withdrawn
//!   capability model (PRD-001 R44) is still in those bytes, and must still decode and
//!   re-encode exactly.
//!
//! Each room's full id is read from v0.2.9 (`vox room invite` and `vox serve`'s address,
//! `vox://<room id>…`). Then this build's daemon starts on the same profile, given each room's
//! passphrase as a person gives them. Asserted, as PRODUCT:
//! 1. this build lists and opens both rooms;
//! 2. it prints the same full id for each, in its invite;
//! 3. it reads each (`vox room read` exits 0).
//!
//! Mutation that must turn it red: this build's genesis encoder writes the retired slot as the
//! deniable value (`1`). Every v0.2.9 room then hashes to another id, and this build refuses to
//! open it.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use previous_release::{previous_release, PREVIOUS};
use world::{after_label, args, echo_service, tempdir, VoxProc, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(90);
const ROOM_PASS: &str = "room pass";

/// Run `exe` (this build's `vox` or the previous release's) to completion on the profile at
/// `data`: whether it succeeded, and what it said.
fn vox_with(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {}: {e}", exe.display()));
    if let Some(s) = stdin {
        // A `vox` that exits without reading its stdin closes the pipe; what it said is the answer.
        let _ = child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(s.as_bytes());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for {}: {e}", exe.display()));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A `vox daemon` of `exe` on `data`, once it answers `vox room list`. v0.2.9's daemon takes the
/// identity passphrase only from a file or stdin, so it is given a file: the identity passphrase,
/// then one room passphrase per line, which is how a person opens their rooms at start.
fn daemon(exe: &Path, name: &str, data: &Path, rooms: &[&str]) -> VoxProc {
    let pass = data.join("identity-passphrase");
    let mut lines = vec![IDENTITY];
    lines.extend_from_slice(rooms);
    std::fs::write(&pass, lines.join("\n") + "\n")
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass.display()));
    let mut p = VoxProc::spawn_exe(
        exe,
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]),
        &[],
    );
    let deadline = Instant::now() + TIMEOUT;
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox_with(exe, data, &["room", "list"], None);
        if ok {
            return p;
        }
        last = format!("{out}{err}");
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "CANNOT MEASURE: {name} never answered `vox room list` in {TIMEOUT:?}; it said:\n{}\n\
         `vox room list` said: {last}",
        p.transcript()
    );
}

/// A line the previous release must print for the staging to go on. Whatever v0.2.9 does instead
/// — exits, or says nothing — is the staging failing, never this build's verdict.
fn staged(p: &mut VoxProc, what: &str, pred: impl Fn(&str) -> bool) -> String {
    p.try_expect_within(TIMEOUT, what, pred)
        .unwrap_or_else(|why| panic!("CANNOT MEASURE: {PREVIOUS}'s staging did not happen: {why}"))
}

/// The room's 12-character prefix as `vox room list` prints it, for the room named `name`.
fn listed(list: &str, name: &str) -> Option<String> {
    list.lines()
        .find(|l| l.split_whitespace().any(|w| w == name))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_owned)
}

/// The full room id in a `vox://<room id>…` address.
fn room_of(address: &str) -> Option<String> {
    let rest = address.trim().strip_prefix("vox://")?;
    let id: String = rest
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (id.len() == 52).then_some(id)
}

#[test]
#[ignore = "two vox builds, one fetched, with production Argon2id; CI runs it in release"]
fn a_room_made_by_the_last_release_keeps_its_name() {
    watchdog::arm();
    let old = previous_release();
    let tmp = tempdir();
    let host = tmp.path().join("host");

    // ---- v0.2.9 makes a chat room and a service room on one profile ----
    let (ok, out, err) = vox_with(&old, &host, &["id"], None);
    assert!(
        ok,
        "CANNOT MEASURE: {PREVIOUS}'s `vox id` failed: {out}{err}"
    );

    let old_daemon = daemon(&old, &format!("{PREVIOUS}'s daemon"), &host, &[]);
    let (ok, out, err) = vox_with(
        &old,
        &host,
        &["room", "create", "--name", "chat"],
        Some(ROOM_PASS),
    );
    assert!(
        ok,
        "CANNOT MEASURE: {PREVIOUS}'s `vox room create` failed: {out}{err}"
    );
    let (_, list, _) = vox_with(&old, &host, &["room", "list"], None);
    let chat = listed(&list, "chat")
        .unwrap_or_else(|| panic!("CANNOT MEASURE: {PREVIOUS} does not list its room: {list}"));
    let (ok, invite, err) = vox_with(&old, &host, &["room", "invite", &chat], None);
    let chat_id = room_of(&invite).unwrap_or_else(|| {
        panic!(
            "CANNOT MEASURE: {PREVIOUS}'s `vox room invite` (ok {ok}) named no room: {invite}{err}"
        )
    });
    drop(old_daemon);

    // v0.2.9's `vox serve` will not mint an address without an anchor; it gets its own.
    let mut anchor = VoxProc::spawn_exe(
        &old,
        &format!("{PREVIOUS}'s anchor"),
        &tmp.path().join("anchor"),
        &args(&["node", "--listen", "127.0.0.1:0"]),
        &[],
    );
    let spec = staged(&mut anchor, "its --anchor spec", |l| {
        l.trim_start().contains("@/ip4/127.0.0.1/udp/")
    })
    .trim()
    .to_owned();
    let mut serve = VoxProc::spawn_exe(
        &old,
        &format!("{PREVIOUS}'s vox serve"),
        &host,
        &args(&[
            "serve",
            &echo_service().to_string(),
            "--name",
            "svc",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &spec,
        ]),
        &[],
    );
    let address = after_label(
        &staged(&mut serve, "its address", |l| l.starts_with("address ")),
        "address",
    );
    let svc_id = room_of(&address).unwrap_or_else(|| {
        panic!("CANNOT MEASURE: {PREVIOUS}'s `vox serve` printed no room address: {address}")
    });
    let svc_pass = after_label(
        &staged(&mut serve, "its room passphrase", |l| {
            l.starts_with("passphrase ")
        }),
        "passphrase",
    );
    // `serving` comes after the room is stored and its service offered.
    staged(&mut serve, "that it is serving", |l| {
        l.starts_with("serving ")
    });
    drop(serve);
    drop(anchor);
    eprintln!("[proof] {PREVIOUS} made chat {chat_id} and svc {svc_id}");

    // ---- this build, on the same profile, given both rooms' passphrases ----
    let _daemon = daemon(
        Path::new(VOX),
        "this build's daemon",
        &host,
        &[ROOM_PASS, &svc_pass],
    );
    for (name, id) in [("chat", &chat_id), ("svc", &svc_id)] {
        let prefix: String = id.chars().take(12).collect();
        // The daemon opens the rooms it was given passphrases for as it starts; wait for that.
        let deadline = Instant::now() + TIMEOUT;
        let mut list: String;
        let open = loop {
            let (ok, out, err) = vox_with(Path::new(VOX), &host, &["room", "list"], None);
            list = format!("{out}{err}");
            let line = out
                .lines()
                .find(|l| l.starts_with(&prefix))
                .map(str::to_owned);
            if ok && line.as_deref().is_some_and(|l| !l.contains("[closed]")) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        assert!(
            open,
            "PRODUCT: this build must list and open the room {PREVIOUS} made as {name} ({id}), \
             given its passphrase; after {TIMEOUT:?} `vox room list` says: {list}"
        );
        let (ok, invite, err) = vox_with(Path::new(VOX), &host, &["room", "invite", &prefix], None);
        assert!(
            ok && room_of(&invite).as_ref() == Some(id),
            "PRODUCT: the room {PREVIOUS} made as {name} must keep its name {id}; this build's \
             invite says: {invite}{err}"
        );
        let (ok, out, err) = vox_with(Path::new(VOX), &host, &["room", "read", &prefix], None);
        assert!(
            ok,
            "PRODUCT: this build must read the room {PREVIOUS} made as {name} ({id}): {out}{err}"
        );
        eprintln!("[proof] this build lists, opens, names and reads {name} as {id}");
    }
}
