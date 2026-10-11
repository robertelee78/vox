//! V030-46 (#423, ADR-026 F-3) — **Vox carries no code for data from earlier releases: a fresh
//! data root works end to end, and one laid out by a release before v0.3.0 is refused with a
//! plain reason and left byte for byte unchanged**, through the shipped binary.
//!
//! Nobody has run a Vox release (decider, 2026-10-04), so nothing needs migrating: Vox carries no
//! code that reads, converts or moves such a data root. What is left is a refusal, before anything
//! is written.
//!
//! **Arm 1, fresh data roots, end to end** (`support/room.rs`): an anchor and two members, each
//! made by `vox id`, attached in its own `vox daemon`; `vox room create`, `invite`, `join` and
//! `trust add`; each posts until the other reads it. Then bob posts once more and alice reads it.
//!
//! **Arm 2, a data root of an earlier release.** A data root laid out as v0.2.x left it: a
//! directory `default/` of the root itself holding `vault.cbor`, `store.redb` and `port` (their
//! contents do not matter: they must never be read), beside a file of the person's own. Every way
//! in is tried — `vox id`, `vox node list`, `vox node attach default`, `vox room list`,
//! `vox status`, `vox daemon` and `vox node` — and each must fail, saying "<root> is not a Vox
//! data directory this version reads: <root>/default is not a node", and never "profile". The
//! data root is snapshotted before and after (every path, every file's bytes): it must be
//! identical. The config directory and `HOME` are outside it, so nothing legitimate writes inside
//! it.
//!
//! **Arm 3, a data root of the previous published release** (ADR-026 F-3, decider 2026-10-08):
//! made by that release, downloaded and digest-checked, and opened by this build with nothing lost
//! ([`a_data_root_of_the_previous_release_opens_with_nothing_lost`]). It runs before every
//! release.
//!
//! **Which side a red is on.** A verb that succeeds, one that refuses for another reason, or a
//! data root that changed is `PRODUCT:`; the proof's own I/O is `APPARATUS:`.
//!
//! The same refusal as the macOS app's login item (`vox daemon --no-node --login-item`, run by
//! launchd, which starts it again after any failed exit) must end with status 0 and its reason in
//! `~/Library/Logs/Vox/login-item.log` (`HOME` is the proof's): not a restart every ten seconds.
//! Mutation: `--login-item` ignored (the refusal an error as before) → red: status 1, no log.
//!
//! Mutation: the refusal removed (`refuse_old_layout` answering `Ok`) → red: the verbs run, and
//! `nodes/` and `.daemon/` appear in the old data root.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "support/room.rs"]
mod room;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The binary under proof.
const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// An identity passphrase, for a verb that would ask for one (none gets that far).
const IDENTITY: &str = "identity passphrase";

/// What every refusal must say.
const REASON: &str = "is not a Vox data directory this version reads";
/// What it says of the directory that is not a node.
const NOT_A_NODE: &str = "is not a node";

/// Every path under `root` with its bytes (`None` for a directory; a fixed marker for a socket or
/// a link).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("APPARATUS: listing {}: {e}", dir.display()));
        for e in entries {
            let e = e.unwrap_or_else(|e| panic!("APPARATUS: an entry of {}: {e}", dir.display()));
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .expect("APPARATUS: under the root")
                .to_owned();
            let kind = e
                .file_type()
                .unwrap_or_else(|e| panic!("APPARATUS: the type of {}: {e}", p.display()));
            if kind.is_dir() {
                out.insert(rel, None);
                walk(&p, root, out);
            } else if !kind.is_file() {
                // A socket or a link: its presence is what counts, and it has no bytes to read.
                out.insert(rel, Some(b"(not a regular file)".to_vec()));
            } else {
                let bytes = std::fs::read(&p)
                    .unwrap_or_else(|e| panic!("APPARATUS: reading {}: {e}", p.display()));
                out.insert(rel, Some(bytes));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// `vox <argv>` on data root `data`, with the config directory and `HOME` outside it, killed by
/// its PID if it has not ended within a minute (a daemon that started anyway). `(exited ok, what
/// it said)`; `None` for the exit when it had to be killed.
fn run_on(data: &Path, outside: &Path, argv: &[&str]) -> (Option<bool>, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", outside.join("cfg"))
        .env("HOME", outside.join("home"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {argv:?}: {e}"));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s.success()),
            Ok(None) if started.elapsed() < Duration::from_secs(60) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                break None;
            }
            Err(e) => panic!("APPARATUS: cannot poll vox {argv:?}: {e}"),
        }
    };
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox {argv:?}: {e}"));
    (
        status,
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
#[ignore = "an anchor and two real daemons with production Argon2id; run in release"]
fn a_fresh_data_root_works_end_to_end() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let r = rt.block_on(room::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let posted = "written on a fresh data root";
    let out = bob.vox(None, &["room", "post", &r.id, posted]);
    assert!(
        out.ok,
        "PRODUCT: bob's `vox room post` failed: {}",
        out.stderr.trim()
    );
    let until = Instant::now() + Duration::from_secs(60);
    let read = loop {
        let out = alice.vox(None, &["room", "read", &r.id]);
        if out.ok && out.stdout.contains(posted) {
            break true;
        }
        if Instant::now() > until {
            break false;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!(
        "[proof] fresh data roots: room {} created, joined, trusted; alice reads bob's post: {read}",
        r.id
    );
    assert!(
        read,
        "PRODUCT: alice never read bob's post on fresh data roots"
    );
}

#[test]
#[ignore = "real binaries; run in release"]
fn a_data_root_of_an_earlier_release_is_refused_and_unchanged() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let data = tmp.path().join("data");
    let outside = tmp.path().join("outside");
    for d in [
        data.join("default"),
        outside.join("cfg"),
        outside.join("home"),
    ] {
        std::fs::create_dir_all(&d).expect("APPARATUS: staging directories");
    }
    // A data root as v0.2.x left it: a node's files in a directory of the root itself.
    let folder = data.join("default");
    std::fs::write(folder.join("vault.cbor"), b"a vault of an earlier release")
        .expect("APPARATUS: staging vault.cbor");
    std::fs::write(folder.join("store.redb"), b"a store of an earlier release")
        .expect("APPARATUS: staging store.redb");
    std::fs::write(folder.join("port"), b"41234\n").expect("APPARATUS: staging port");
    std::fs::write(data.join("notes.txt"), b"a file of the person's own")
        .expect("APPARATUS: staging notes.txt");
    let before = snapshot(&data);

    let verbs: [&[&str]; 7] = [
        &["id"],
        &["node", "list"],
        &["node", "attach", "default"],
        &["room", "list"],
        &["status"],
        &["daemon", "--listen", "127.0.0.1:0"],
        &["node", "--listen", "127.0.0.1:0"],
    ];
    let mut red = Vec::new();
    for argv in verbs {
        let (status, said) = run_on(&data, &outside, argv);
        let names_it = said.contains(&format!("{} {REASON}", data.display()))
            && said.contains(&format!("{} {NOT_A_NODE}", folder.display()))
            && !said.to_lowercase().contains("profile");
        println!(
            "[proof] vox {}: exit ok = {status:?}; says why = {names_it}",
            argv.join(" ")
        );
        if status != Some(false) || !names_it {
            red.push(format!(
                "`vox {}` must fail saying the data root {REASON} and that {} {NOT_A_NODE}, \
                 never \"profile\"; it ended {status:?} and said: {said}",
                argv.join(" "),
                folder.display()
            ));
        }
    }
    // **The login item** (the macOS app's launchd agent, `--login-item`): launchd starts it again
    // after any failed exit, so a refusal no retry can change ends with status 0 and its reason in
    // ~/Library/Logs/Vox/login-item.log, where the app quotes it; nothing else changes.
    let log = outside.join("home/Library/Logs/Vox/login-item.log");
    let (status, said) = run_on(&data, &outside, &["daemon", "--no-node", "--login-item"]);
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    let log_names_it = logged.contains(&format!("{} {REASON}", data.display()));
    println!(
        "[proof] vox daemon --no-node --login-item: exit ok = {status:?}; its log says why = \
         {log_names_it}"
    );
    if status != Some(true) || !log_names_it {
        red.push(format!(
            "as the login item, a data root this version does not read must end the daemon with \
             status 0 (launchd then leaves it) and its reason in {}; it ended {status:?}, said \
             {said:?}, and the log holds {logged:?}",
            log.display()
        ));
    }
    let after = snapshot(&data);
    if after != before {
        let added: Vec<_> = after.keys().filter(|k| !before.contains_key(*k)).collect();
        let changed: Vec<_> = before
            .iter()
            .filter(|(k, v)| after.get(*k) != Some(v))
            .map(|(k, _)| k)
            .collect();
        red.push(format!(
            "the refused data root changed: added {added:?}; changed or removed {changed:?}"
        ));
    }
    println!(
        "[proof] the data root after every verb: {} paths, unchanged = {}",
        after.len(),
        after == before
    );
    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}

/// Read the actual Session, including its full detail, through the worker's shipped CLI.
fn assert_upgrade_steps(w: &room::Worker, room: &str, present: bool) {
    let session = format!("upgrade-step-{}", w.name);
    let marker = format!("STEP-BEFORE-UPGRADE-{}", w.name);
    let o = w.vox(
        None,
        &["room", "session", room, &session, "--details", "--json"],
    );
    assert!(
        o.ok && o.stdout.contains(&marker) == present,
        "PRODUCT: {}'s Session must have old step present={present}; got {o:?}",
        w.name
    );
}

/// The user's status, rather than a private policy or store value, reports effective retention.
fn assert_retention(w: &room::Worker, room: &str, messages: u64, steps: u64) {
    let o = w.vox(None, &["status", "--json"]);
    assert!(o.ok, "PRODUCT: {} could not read status: {o:?}", w.name);
    let status: serde_json::Value = serde_json::from_str(&o.stdout)
        .unwrap_or_else(|e| panic!("PRODUCT: status is not JSON: {e}: {}", o.stdout));
    let row = status["rooms"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(room)))
        .unwrap_or_else(|| panic!("PRODUCT: status omitted room {room}: {}", o.stdout));
    assert_eq!(
        (row["retention"].as_u64(), row["step_retention"].as_u64()),
        (Some(messages), Some(steps)),
        "PRODUCT: {}'s status does not show the effective message and step retention: {row}",
        w.name
    );
}

fn await_upgrade_post(w: &room::Worker, room: &str, text: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let o = w.vox(None, &["room", "read", room, "--limit", "1000"]);
        if o.ok && o.stdout.contains(text) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: {} never read {text:?} within 60 seconds: {o:?}",
            w.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// What a person sees of their node, read by `exe`: its fingerprint, the fingerprints in its
/// keyring, its rooms, and the room's rows as `(entry hash, author, created ms, text)`.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    id: String,
    keyring: Vec<String>,
    rooms: Vec<String>,
    rows: Vec<(String, String, u64, String)>,
}

/// [`Seen`] by `w`'s `vox`; a verb that fails is a red on `side` (`APPARATUS:` while the old
/// release stages, `PRODUCT:` for this build).
fn seen(w: &room::Worker, room: &str, others: &[String], side: &str) -> Seen {
    let ok = |args: &[&str]| {
        let o = w.vox(None, args);
        assert!(
            o.ok,
            "{side} {}'s `{}` failed (exit {:?}): {} {}",
            w.name,
            o.argv,
            o.code,
            o.stdout.trim(),
            o.stderr.trim()
        );
        o
    };
    let id = ok(&["id"]).stdout.trim().to_owned();
    let ring = &ok(&["trust", "list"]).stdout;
    let squeezed: String = ring.chars().filter(|c| !c.is_whitespace()).collect();
    let keyring = others
        .iter()
        .filter(|fp| squeezed.contains(fp.as_str()))
        .cloned()
        .collect();
    let rooms = ok(&["room", "list"])
        .stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|r| room.starts_with(r))
        .map(str::to_owned)
        .collect();
    let rows = ok(&["room", "read", room, "--json", "--limit", "1000"])
        .ndjson()
        .iter()
        .map(|r| {
            (
                r["entry_hash"].as_str().unwrap_or_default().to_owned(),
                r["author"].as_str().unwrap_or_default().to_owned(),
                r["created_millis"].as_u64().unwrap_or_default(),
                r["text"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    Seen {
        id,
        keyring,
        rooms,
        rows,
    }
}

/// ADR-026 F-3 — **a data root the previous published release wrote opens in this build with
/// nothing lost.** The previous release (downloaded, digest-checked) makes an anchor and two
/// members, alice and bob: a room, trust both ways, posts each way and a share. Each member's
/// view is read with that release. Then every process is stopped as a person stops it and started
/// again from this build on the same data roots, and each member must see the same fingerprint,
/// the same keyring, the same room, and the same rows in the same order with the same times; the
/// share must still be listed; `.daemon/format` must say format 2, written by this build; and,
/// once each member's daemon is started again by this build, so that it reads back what this build
/// rewrote, a post written after the upgrade must reach the other member.
///
/// Run before every release with the newest published release as the source (`VOX_UPGRADE_FROM`
/// names another), with `--features test-knobs`; it needs GitHub unless
/// `VOX_PREVIOUS_RELEASE_DIR` contains the published artifact and its digest record.
///
/// ADR-034 FR-5 / #789: old hook activity survives the upgrade, the default seven-day step
/// policy is separate from forever messages, members may shorten but never lengthen it, and
/// an actual old peer keeps exchanging messages after the new policy event. At three days a
/// member's two-day limit has removed only its steps; at eight days both members' expired
/// steps are absent immediately and after restart, while forever messages remain.
/// Mutants: classify every Session entry as a message → expired steps remain; ignore a member's
/// step limit → its step remains at three days; apply step TTL to messages → forever posts vanish.
///
/// **Which side a red is on.** A download, a digest or a staging step of the old release that
/// fails is `APPARATUS:`; this build failing a verb, or seeing anything other than what the old
/// release saw, is `PRODUCT:`.
///
/// Mutant: the vault's AEAD label changed in this build (`VAULT_AAD_V2`) → red, `PRODUCT:` this
/// build cannot unlock the node the previous release made.
///
/// Mutants of the prekey ring's upgrade (ADR-030 P-1, ring version 3): the previous release's
/// version 2 no longer read (`RING_VERSION_NO_RETIRED`'s arm in `PrekeyRing::decode` removed) →
/// red, `PRODUCT:` this build cannot unlock the node; the retired set left out of the version-3
/// encoding → red at the restart, `PRODUCT:` the daemon this build started again cannot unlock the node.
#[test]
#[ignore = "downloads the previous release; an anchor and two daemons of each; run in release"]
fn a_data_root_of_the_previous_release_opens_with_nothing_lost() {
    watchdog::arm_for(Duration::from_secs(1200));
    assert!(
        cfg!(feature = "test-knobs"),
        "APPARATUS: the upgrade retention journey requires --features test-knobs"
    );
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let (version, old) = previous_release::previous_release(tmp.path());
    let old = old.to_str().expect("APPARATUS: a UTF-8 path").to_owned();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the clock")
        .as_millis();
    let t0 = u64::try_from(t0).expect("APPARATUS: the clock");
    let mut r = rt.block_on(room::room_as(tmp.path(), &["alice", "bob"], &old));

    // What a person has made with the previous release: posts each way, a second apart, and a
    // share with a note.
    let fps: Vec<String> = r.workers.iter().map(room::Worker::b32).collect();
    let staged = |what: &str, o: &room::Out| {
        assert!(
            o.ok,
            "APPARATUS: staging with v{version}: {what} failed: {}",
            o.stderr.trim()
        );
    };
    staged(
        "forever message retention",
        &r.workers[0].vox(None, &["room", "retention", &r.id, "forever"]),
    );
    // Use the published hook and its published daemon together. A current IPC client would
    // couple this upgrade proof to an old, deliberately incompatible local protocol.
    for w in &r.workers {
        let session = format!("upgrade-step-{}", w.name);
        let transcript = tmp.path().join(format!("{session}.jsonl"));
        std::fs::write(&transcript, "").expect("APPARATUS: the old hook's transcript");
        let node = w.paths.account().nodes_on_disk()[0].clone();
        let payload = serde_json::json!({
            "session_id": session,
            "transcript_path": transcript,
            "cwd": tmp.path(),
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("STEP-BEFORE-UPGRADE-{}", w.name),
            "prompt_id": "upgrade-prompt",
        })
        .to_string();
        staged(
            "Session activity through the old hook",
            &w.vox_env(
                None,
                &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
                &["agent", "hook", "--node", node.as_str(), "--room", &r.id],
                Some(&payload),
            ),
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let o = w.vox(
                None,
                &["room", "session", &r.id, &session, "--details", "--json"],
            );
            if o.ok
                && o.stdout
                    .contains(&format!("STEP-BEFORE-UPGRADE-{}", w.name))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: v{version} did not stage {}'s hook activity: {o:?}",
                w.name
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    for n in 1..=3 {
        for w in &r.workers {
            let text = format!("upgrade: {} {n}", w.name);
            staged(&text, &w.vox(None, &["room", "post", &r.id, &text]));
        }
        std::thread::sleep(Duration::from_millis(1100));
    }
    let file = tmp.path().join("upgrade-note.txt");
    std::fs::write(&file, b"shared before the upgrade").expect("APPARATUS: the shared file");
    staged(
        "alice's share",
        &r.workers[0].vox(
            None,
            &[
                "share",
                &r.id,
                file.to_str().unwrap_or_default(),
                "-m",
                "upgrade share",
            ],
        ),
    );
    // Staged when each member reads every post of the other's and the share.
    let room_id = r.id.clone();
    let deadline = Instant::now() + Duration::from_secs(120);
    let all_read = |w: &room::Worker| {
        let o = w.vox(None, &["room", "read", &room_id, "--limit", "1000"]);
        o.ok && (1..=3).all(|n| {
            o.stdout.contains(&format!("upgrade: alice {n}"))
                && o.stdout.contains(&format!("upgrade: bob {n}"))
        }) && o.stdout.contains("upgrade-note.txt")
    };
    while !r.workers.iter().all(all_read) {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: staging with v{version}: the members never read each other's posts and \
             the share within 120 s"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let shares = |w: &room::Worker| {
        let o = w.vox(None, &["share", "list", &room_id]);
        o.ok && o.stdout.contains("upgrade-note.txt")
    };
    assert!(
        shares(&r.workers[0]),
        "APPARATUS: staging with v{version}: alice's `vox share list` does not list her share"
    );
    let before: Vec<Seen> = r
        .workers
        .iter()
        .map(|w| seen(w, &r.id, &fps, "APPARATUS: staging:"))
        .collect();
    for (w, s) in r.workers.iter().zip(&before) {
        assert!(
            s.rows.len() >= 7 && s.keyring.len() == 1 && s.rooms.len() == 1,
            "APPARATUS: staging with v{version}: {} sees {} rows, keyring {:?}, rooms {:?}",
            w.name,
            s.rows.len(),
            s.keyring,
            s.rooms
        );
    }

    // Upgrade alice first. Bob remains an actual published daemon and CLI on his original
    // data root while the room receives a new step-retention policy event.
    let legacy = r.workers.pop().expect("APPARATUS: bob exists");
    r.upgrade(VOX);
    assert_eq!(
        seen(&r.workers[0], &r.id, &fps, "PRODUCT:"),
        before[0],
        "PRODUCT: alice lost data when her v{version} root was first upgraded"
    );
    assert_upgrade_steps(&r.workers[0], &r.id, true);
    assert_retention(&r.workers[0], &r.id, 0, 7 * 86400);
    for ttl in ["1d", "7d"] {
        let o = r.workers[0].vox(None, &["room", "retention", &r.id, "--steps", ttl]);
        assert!(
            o.ok,
            "PRODUCT: the administrator could not set separate step retention: {o:?}"
        );
    }
    assert_retention(&r.workers[0], &r.id, 0, 7 * 86400);
    let compatible = "published peer after the step policy update";
    let o = legacy.vox(None, &["room", "post", &r.id, compatible]);
    assert!(
        o.ok,
        "PRODUCT: v{version} could not post after the new policy event: {o:?}"
    );
    await_upgrade_post(&r.workers[0], &r.id, compatible);
    let response = "new peer answers the published peer after the step policy update";
    let o = r.workers[0].vox(None, &["room", "post", &r.id, response]);
    assert!(
        o.ok,
        "PRODUCT: the new peer could not answer the published peer: {o:?}"
    );
    await_upgrade_post(&legacy, &r.id, response);
    println!(
        "[proof] v{version} and this build exchange ordinary messages after a step policy update"
    );
    r.workers.push(legacy);
    // Bob's baseline is still read by the published CLI. Include the just-proven conversation
    // in both baselines, then upgrade both together, as a person completes a rolling upgrade.
    let before: Vec<Seen> = r
        .workers
        .iter()
        .map(|w| seen(w, &r.id, &fps, "PRODUCT:"))
        .collect();
    let t1 = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("APPARATUS: the clock")
            .as_millis(),
    )
    .expect("APPARATUS: the clock");
    r.upgrade(VOX);
    let mut red = Vec::new();
    for (w, b) in r.workers.iter().zip(&before) {
        let a = seen(w, &r.id, &fps, "PRODUCT:");
        let times_ok = a.rows.iter().all(|(_, _, t, _)| (t0..=t1).contains(t));
        println!(
            "[proof] {}: fingerprint same {}; keyring same {}; room same {}; {} rows, same and in \
             order {}; every time inside the staging window {times_ok}",
            w.name,
            a.id == b.id,
            a.keyring == b.keyring,
            a.rooms == b.rooms,
            a.rows.len(),
            a.rows == b.rows
        );
        if a != *b || !times_ok {
            red.push(format!(
                "{} after the upgrade from v{version} sees {a:#?}; with v{version} it saw {b:#?}; \
                 every time inside [{t0}, {t1}]: {times_ok}",
                w.name
            ));
        }
        let format = std::fs::read_to_string(w.data.join(".daemon/format")).unwrap_or_default();
        let want = format!("format 2\nwritten-by vox {}\n", env!("CARGO_PKG_VERSION"));
        if format != want {
            red.push(format!(
                "{}'s .daemon/format says {format:?}; this build serving it must write {want:?}",
                w.name
            ));
        }
    }
    let listed = shares(&r.workers[0]);
    println!("[proof] alice's share still listed: {listed}");
    if !listed {
        red.push("alice's `vox share list` no longer lists her share after the upgrade".to_owned());
    }
    // Started once more by this build, each node reads back what this build wrote of what the
    // previous release left: the prekey ring, read at the previous release's at-rest version and
    // saved at once at this build's (ADR-030 P-1 adds the retired one-time prekeys).
    for i in 0..r.workers.len() {
        r.restart(i);
    }
    // And the room still works: a post after the upgrade reaches the other member.
    let after = "written after the upgrade";
    let posted = r.workers[1].vox(None, &["room", "post", &r.id, after]);
    let deadline = Instant::now() + Duration::from_secs(60);
    let reached = posted.ok
        && loop {
            let o = r.workers[0].vox(None, &["room", "read", &r.id, "--limit", "1000"]);
            if o.ok && o.stdout.contains(after) {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(500));
        };
    println!("[proof] bob's post after the upgrade reached alice: {reached}");
    if !reached {
        red.push(format!(
            "bob's post after the upgrade never reached alice in 60 s (post: {})",
            posted.stderr.trim()
        ));
    }
    assert!(red.is_empty(), "PRODUCT: {red:#?}");
    for w in &r.workers {
        assert_upgrade_steps(w, &r.id, true);
        assert_retention(w, &r.id, 0, 7 * 86400);
    }
    let bob = &r.workers[1];
    for ttl in ["8d", "forever"] {
        let o = bob.vox(None, &["room", "retention", &r.id, "--steps", ttl]);
        assert!(!o.ok && o.stderr.contains("room"),
            "PRODUCT: a member could extend steps beyond the room's seven-day cap, or got no reason: {o:?}");
    }
    // What status shows must include the message cap, even when the member asks for more steps.
    for args in [
        vec!["room", "retention", &r.id, "1h"],
        vec!["room", "retention", &r.id, "--steps", "7d"],
    ] {
        let o = bob.vox(None, &args);
        assert!(
            o.ok,
            "PRODUCT: setting the member's retention failed: {o:?}"
        );
    }
    assert_retention(bob, &r.id, 3600, 3600);
    let o = bob.vox(None, &["room", "retention", &r.id, "forever"]);
    assert!(
        o.ok,
        "PRODUCT: the member could not follow forever messages again: {o:?}"
    );
    let o = bob.vox(None, &["room", "retention", &r.id, "--steps", "2d"]);
    assert!(
        o.ok,
        "PRODUCT: a member could not shorten its own steps to two days: {o:?}"
    );
    assert_retention(bob, &r.id, 0, 2 * 86400);
    assert_retention(&r.workers[0], &r.id, 0, 7 * 86400);

    // Only the daemon clock moves. The public CLI reads the room immediately after reopening;
    // there is no delay or retry that could hide a briefly visible expired step.
    for (days, restart) in [(3_u64, false), (8, false), (8, true)] {
        let step_ms = (days * 86400 * 1000).to_string();
        for w in &mut r.workers {
            let err = tmp
                .path()
                .join(format!("{}.day-{days}.restart-{restart}.err", w.name));
            w.restart_daemon_as(VOX, &[("VOX_TEST_CLOCK_STEP_MS", &step_ms)], &err);
            assert_upgrade_steps(w, &r.id, days == 3 && w.name == "alice");
            assert!(
                all_read(w),
                "PRODUCT: {} lost forever messages or the share at day {days}, restart={restart}",
                w.name
            );
            let o = w.vox(None, &["room", "read", &r.id, "--limit", "1000"]);
            assert!(
                o.ok && o.stdout.contains(compatible)
                    && o.stdout.contains(response)
                    && o.stdout.contains(after),
                "PRODUCT: {} lost post-upgrade forever messages at day {days}: {o:?}",
                w.name
            );
        }
        println!("[proof] day {days}, restart={restart}: step expiry is visible on first read; forever messages remain");
    }
}
