//! V030-05 (#237), ported to v0.2.10 as V210-83 (#274) — **the profile-busy message is true, and
//! `vox serve`'s printed steps can be done while it runs**, whatever holds the profile, through
//! the shipped binary.
//!
//! redb is single-writer, so while one `vox` holds a profile a second process that opens it is
//! refused, and the refusal says: "a vox is already running for this profile … Its control socket
//! is <path> … use the `vox room …` verbs, which ask the running node instead of starting a
//! second one." That was true of a `vox daemon` and false of every one-shot verb that holds a
//! profile while it runs — `serve`, `connect`, `service`, `forward`, `up`, `lan up` — none of
//! which served a control socket: the path named did not exist and the remedy named was refused.
//!
//! **What must hold, for each holder** — a host's `vox serve` (the room-making verbs' path) and a
//! guest's `vox forward` (the tunnel verbs' path):
//!
//! 1. a second one-shot verb on the held profile is refused, with the message;
//! 2. the control socket the message names **exists and is a socket**;
//! 3. the remedy it names **works**: `vox room list` succeeds while the holder runs, through
//!    that socket, and lists the room the holder has open; and `vox status --json` answers;
//! 4. the steps `vox serve` prints **work while it runs** (V210-83): "ask them for `vox id`,
//!    then run `vox trust add <fingerprint>`" and "`vox trust list` shows who you have decided
//!    about". Both are run against each holder, and the one trusted must then be listed.
//!
//! Mutation: not binding the control socket for the one-shot verbs (`serve_control_socket` never
//! called) turns (2), (3) and (4) red for both holders.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use relay::{RelayWorld, Split};
use world::{args, vox_once};

/// Everything wrong with how `dir`'s profile answers while something holds it.
fn check_holder(holder: &str, dir: &Path, room: &str, stranger: &str, failures: &mut Vec<String>) {
    // 1. a second process on the held profile is refused, with the message.
    let (ok, out, err) = vox_once(dir, &args(&["serve", "9", "--listen", "127.0.0.1:0"]));
    let said = format!("{out}{err}");
    eprintln!(
        "[{holder}] a second `vox serve` says: ok={ok}: {}",
        said.trim()
    );
    if ok || !said.contains("already running for this profile") {
        failures.push(format!(
            "{holder}: a second verb was not refused as busy: ok={ok}: {said}"
        ));
        return;
    }
    let Some(socket) = said
        .lines()
        .find_map(|l| l.trim().strip_prefix("Its control socket is "))
        .map(|s| PathBuf::from(s.trim()))
    else {
        failures.push(format!(
            "{holder}: the message names no control socket: {said}"
        ));
        return;
    };
    // 2. the socket it names exists, and is a socket.
    let is_socket = std::fs::metadata(&socket).is_ok_and(|m| m.file_type().is_socket());
    eprintln!("[{holder}] {} is a socket: {is_socket}", socket.display());
    if !is_socket {
        failures.push(format!(
            "{holder}: the control socket it names, {}, is not there",
            socket.display()
        ));
    }
    // 3. the remedy it names works, through the running node.
    let (ok, out, err) = vox_once(dir, &args(&["room", "list"]));
    eprintln!(
        "[{holder}] `vox room list`: ok={ok}: {}{}",
        out.trim(),
        err.trim()
    );
    if !ok || !out.contains(room) {
        failures.push(format!(
            "{holder}: `vox room list` did not answer with the room {room}: ok={ok}: {out}{err}"
        ));
    }
    let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
    let answered = ok && serde_json::from_str::<serde_json::Value>(out.trim()).is_ok();
    eprintln!("[{holder}] `vox status --json` answered: {answered}");
    if !answered {
        failures.push(format!(
            "{holder}: `vox status --json` did not answer: ok={ok}: {out}{err}"
        ));
    }
    // 4. `vox serve`'s printed steps, done while the holder runs.
    let (ok, out, err) = vox_once(
        dir,
        &args(&["trust", "add", stranger, "--name", "a stranger"]),
    );
    eprintln!(
        "[{holder}] `vox trust add`: ok={ok}: {}{}",
        out.trim(),
        err.trim()
    );
    if !ok {
        failures.push(format!(
            "{holder}: `vox trust add`, a step `vox serve` prints, failed: {out}{err}"
        ));
    }
    let (ok, out, err) = vox_once(dir, &args(&["trust", "list"]));
    eprintln!(
        "[{holder}] `vox trust list`: ok={ok}: {}{}",
        out.trim(),
        err.trim()
    );
    if !ok || !out.contains(stranger) {
        failures.push(format!(
            "{holder}: `vox trust list` did not list the identity just trusted: ok={ok}: {out}{err}"
        ));
    }
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn whatever_holds_a_profile_answers_for_it() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT MEASURE: staging not achieved — the guest could not join ({took:?}).\n{out}\n{err}"
    );
    w.forward();
    let room: String = w.room.chars().take(12).collect();
    // Someone to trust: a third profile's fingerprint, as `vox id` prints it.
    let third = w.tmp.path().join("third");
    std::fs::create_dir_all(third.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", third.display()));
    let (ok, stranger, err) = vox_once(&third, &args(&["id"]));
    assert!(
        ok,
        "CANNOT MEASURE: staging not achieved — `vox id` for a third profile failed: {err}"
    );
    let stranger = stranger.trim().to_owned();

    let mut failures = Vec::new();
    for (holder, dir) in [
        ("vox serve", w.host_dir.clone()),
        ("vox forward", w.guest_dir.clone()),
    ] {
        check_holder(holder, &dir, &room, &stranger, &mut failures);
    }
    eprintln!("[proof] 2 holders checked, {} failures", failures.len());
    assert!(
        failures.is_empty(),
        "PRODUCT: a profile's holder does not answer for it: {failures:#?}"
    );
}
