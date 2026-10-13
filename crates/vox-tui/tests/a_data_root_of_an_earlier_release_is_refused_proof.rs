//! V030-46 (#423, ADR-026 F-3) — a fresh data root works end to end, supported roots from v0.4.0
//! onward upgrade, and an unsupported layout or format is refused before anything is written.
//! A format from a newer Vox, or a damaged marker, must not be mistaken for a supported old root.
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
//! The same journey also tries a current-layout root with a future format and a damaged marker
//! (#741). Neither may be opened, stamped with this build's format, or otherwise changed.
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
//! Mutation for #741: skip `data_root_format` at admission → PRODUCT red when `vox node list`
//! succeeds on the future root instead of saying that a newer Vox is needed.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "support/room.rs"]
mod room;

#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod raw_sync;

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

    // An unsupported format is as dangerous to open as an unsupported directory layout.
    // The marker and opaque store are test-side apparatus; the verdict is the shipped CLI's
    // refusal and the person's data remaining unchanged, not a parser's internal result.
    for (name, marker, reason) in [
        (
            "future-format",
            "format 4294967295\nwritten-by vox future\n",
            "needs a newer Vox",
        ),
        (
            "damaged-format",
            "format interrupted\n",
            "format marker is not valid",
        ),
        ("broken-format-link", "", "format marker could not be read"),
        ("linked-format", "", "format marker could not be read"),
    ] {
        let data = tmp.path().join(name);
        std::fs::create_dir_all(data.join(".daemon")).expect("APPARATUS: the format directory");
        std::fs::create_dir_all(data.join("nodes/default")).expect("APPARATUS: the node directory");
        if name == "broken-format-link" {
            std::os::unix::fs::symlink("missing-format", data.join(".daemon/format"))
                .expect("APPARATUS: the broken format marker");
        } else if name == "linked-format" {
            // The text is supported; following the link would admit the root. The marker
            // itself must be a regular file, rather than an unchecked indirect read.
            let target = outside.join("linked-format");
            std::fs::write(&target, "format 2\nwritten-by vox 0.4.4\n")
                .expect("APPARATUS: the linked marker's target");
            std::os::unix::fs::symlink(&target, data.join(".daemon/format"))
                .expect("APPARATUS: the linked format marker");
        } else {
            std::fs::write(data.join(".daemon/format"), marker)
                .expect("APPARATUS: the unsupported format marker");
        }
        std::fs::write(
            data.join("nodes/default/store.redb"),
            b"do not open this store",
        )
        .expect("APPARATUS: the person's store");
        std::fs::write(data.join("notes.txt"), b"a file of the person's own")
            .expect("APPARATUS: the person's notes");
        let before = snapshot(&data);
        // List first: a mutant that removes admission must turn red immediately, rather than
        // relying on a watchdog after accidentally starting a daemon.
        for argv in std::iter::once(&["node", "list"][..])
            .chain(verbs.into_iter().filter(|argv| *argv != ["node", "list"]))
        {
            let (status, said) = run_on(&data, &outside, argv);
            assert!(
                status == Some(false) && said.contains(REASON) && said.contains(reason),
                "PRODUCT: {name}: vox {argv:?} must refuse with {reason:?}; \
                 exit ok={status:?}, said {said:?}"
            );
            assert_eq!(
                snapshot(&data),
                before,
                "PRODUCT: {name}: vox {argv:?} changed a data root it cannot read"
            );
        }
    }
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
fn assert_retention(w: &room::Worker, room: &str, messages: u64, steps: u64) -> String {
    let o = w.vox(None, &["status", "--json"]);
    assert!(o.ok, "PRODUCT: {} could not read status: {o:?}", w.name);
    let status: serde_json::Value = serde_json::from_str(&o.stdout)
        .unwrap_or_else(|e| panic!("PRODUCT: status is not JSON: {e}: {}", o.stdout));
    let row = status["rooms"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["id"].as_str() == Some(room) || row["name"].as_str() == Some(room))
        })
        .unwrap_or_else(|| panic!("PRODUCT: status omitted room {room}: {}", o.stdout));
    assert_eq!(
        (row["retention"].as_u64(), row["step_retention"].as_u64()),
        (Some(messages), Some(steps)),
        "PRODUCT: {}'s status does not show the effective message and step retention: {row}",
        w.name
    );
    row["id"]
        .as_str()
        .expect("PRODUCT: room status omitted its id")
        .to_owned()
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
/// share must still be listed; `.daemon/format` must say format 3, written by this build; and,
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
#[ignore = "downloads the previous release; scratch anchors and member daemons; run in release"]
fn a_data_root_of_the_previous_release_opens_with_nothing_lost() {
    watchdog::arm_for(Duration::from_secs(1200));
    if !cfg!(feature = "test-knobs") {
        panic!("APPARATUS: the upgrade retention journey requires --features test-knobs");
    }
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
    for (ttl, seconds) in [("1d", 86400), ("7d", 7 * 86400)] {
        let o = r.workers[0].vox(None, &["room", "retention", &r.id, "--steps", ttl]);
        assert!(
            o.ok,
            "PRODUCT: the administrator could not set separate step retention: {o:?}"
        );
        assert_retention(&r.workers[0], &r.id, 0, seconds);
    }
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
        let want = format!("format 3\nwritten-by vox {}\n", env!("CARGO_PKG_VERSION"));
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
    // A newly created room has the same seven-day step default; it is not only an upgrade rule.
    let fresh_pass = tmp.path().join("fresh-room-pass");
    std::fs::write(&fresh_pass, "fresh room passphrase\n")
        .expect("APPARATUS: fresh room passphrase");
    let created = r.workers[0].vox(
        None,
        &[
            "room",
            "create",
            "--name",
            "fresh-retention-default",
            "--passphrase-file",
            fresh_pass.to_str().expect("APPARATUS: UTF-8 path"),
        ],
    );
    assert!(
        created.ok,
        "PRODUCT: could not create a new room after upgrade: {created:?}"
    );
    let fresh = assert_retention(&r.workers[0], "fresh-retention-default", 0, 7 * 86400);
    // The admin's separate step policy still cannot outlive the room's message cap.
    for args in [
        vec!["room", "retention", &fresh, "1h"],
        vec!["room", "retention", &fresh, "--steps", "7d"],
    ] {
        let o = r.workers[0].vox(None, &args);
        assert!(o.ok, "PRODUCT: setting the admin's retention failed: {o:?}");
    }
    assert_retention(&r.workers[0], &fresh, 3600, 3600);
    let help = r.workers[0].vox(None, &["room", "retention", "--help"]);
    let meaning = help.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        help.ok
            && meaning.contains("A step is one thing an agent did in its Session: a message, a command it ran, or a file it edited.")
            && meaning.contains("Retention is housekeeping: a modified node can keep everything."),
        "PRODUCT: retention help does not explain a step and what retention means: {help:?}"
    );
    let bob = &r.workers[1];
    for ttl in ["8d", "forever"] {
        let o = bob.vox(None, &["room", "retention", &r.id, "--steps", ttl]);
        assert!(
            !o.ok && o.stderr.contains("room"),
            "PRODUCT: a member could extend steps beyond the room's seven-day cap, or got no reason: {o:?}"
        );
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
        println!(
            "[proof] day {days}, restart={restart}: step expiry is visible on first read; forever messages remain"
        );
    }
    drop(r);
    legacy_session_copies_upgrade(tmp.path(), &old, &rt);
}

/// The original author asks real daemons for its own encrypted records. This bypasses neither
/// protocol nor authentication; it prevents a recipient-permission filter from concealing a
/// retained copy. The verdict is the daemon's wire response, never an in-process store value.
struct SessionCopies {
    public: Vec<vox_core::log::entry::Entry>,
    private: Vec<Vec<u8>>,
}

fn session_copies_as_owner(
    r: &mut room::Room,
    rt: &tokio::runtime::Runtime,
    upgraded: bool,
) -> Vec<SessionCopies> {
    use vox_core::cbor::{Decoder, Encoder};
    use vox_core::log::entry::Entry;
    use vox_core::transport::framing::{read_frame, write_frame};
    use vox_core::transport::streams::{open_typed, StreamKind};

    let side = if upgraded { "PRODUCT" } else { "APPARATUS" };
    let targets: Vec<_> = r.workers[1..]
        .iter()
        .map(|w| {
            let o = w.vox(None, &["status", "--json"]);
            assert!(
                o.ok,
                "{side}: {} could not report its endpoint: {o:?}",
                w.name
            );
            (
                w.name.clone(),
                w.fp,
                ports::loopback_listen(&o.stdout).expect("APPARATUS: scratch holder endpoint"),
            )
        })
        .collect();
    r.workers[0].stop_daemon();
    let endpoint = rt.block_on(raw_sync::endpoint_as_member(
        &r.workers[0].paths,
        room::ID_PASS.as_bytes(),
    ));
    let mut copies = Vec::new();
    for (name, fingerprint, addr) in targets {
        let conn = rt
            .block_on(endpoint.connect(addr, fingerprint, raw_sync::now()))
            .expect("APPARATUS: original author connects to the scratch holder");
        let y = rt.block_on(raw_sync::ask(
            &conn,
            r.cid,
            0,
            raw_sync::Ask::Everything,
            None,
        ));
        assert!(
            y.hello && y.ended.is_none() && !y.wires.is_empty(),
            "{side}: {name} did not serve its held public history: hello={}, ended={:?}, entries={}",
            y.hello, y.ended, y.wires.len()
        );
        let public = y
            .wires
            .iter()
            .map(|wire| Entry::from_wire(wire).expect("PRODUCT: invalid public entry from holder"))
            .collect();
        let mut private = Vec::new();
        if upgraded {
            let mut incarnation = [0; 32];
            let mut after = 0;
            let mut finished = false;
            for _ in 0..32 {
                let bytes = rt.block_on(async {
                    let (mut send, mut recv) = open_typed(&conn, StreamKind::Session)
                        .await
                        .expect("PRODUCT: original author could not open private Session stream");
                    let mut e = Encoder::new();
                    e.array(5)
                        .uint(1)
                        .bytes(&r.cid)
                        .uint(0)
                        .bytes(&incarnation)
                        .uint(after);
                    write_frame(&mut send, &e.finish())
                        .await
                        .expect("APPARATUS: original author sends private request");
                    send.finish()
                        .expect("APPARATUS: original author finishes private request");
                    read_frame(&mut recv, 4 * 1024 * 1024)
                        .await
                        .expect("PRODUCT: holder's private Session response failed")
                        .expect("PRODUCT: holder gave no private Session response")
                });
                let mut d = Decoder::new(&bytes);
                assert_eq!(
                    d.array().expect("PRODUCT: private page array"),
                    5,
                    "PRODUCT: invalid private Session page shape"
                );
                assert_eq!(
                    d.uint().expect("PRODUCT: private page version"),
                    1,
                    "PRODUCT: invalid private Session page version"
                );
                incarnation = d
                    .bytes()
                    .expect("PRODUCT: private page incarnation")
                    .try_into()
                    .expect("PRODUCT: invalid private page incarnation");
                after = d.uint().expect("PRODUCT: private page cursor");
                let more = d.uint().expect("PRODUCT: private page continuation");
                for _ in 0..d.array().expect("PRODUCT: private page records") {
                    private.push(d.bytes().expect("PRODUCT: private record bytes").to_vec());
                }
                d.finish().expect("PRODUCT: trailing private page bytes");
                if more == 0 {
                    finished = true;
                    break;
                }
                assert_eq!(more, 1, "PRODUCT: invalid private page continuation");
            }
            assert!(
                finished,
                "APPARATUS: staged private history exceeded bounded probe"
            );
        }
        copies.push(SessionCopies { public, private });
    }
    drop(endpoint);
    r.restart(0);
    copies
}

/// Extend the published-release journey with the users for whom a cache-only assertion is
/// insufficient: a current driver, a driver revoked before upgrade, and an ordinary reader.
/// Mutants: skip the public rewrite -> the author's public wire request receives old ciphertext;
/// keep revoked legacy copies -> its private request recovers them; drop authorized copies ->
/// the current driver loses readable history and/or the original signed private record.
fn legacy_session_copies_upgrade(root: &Path, old: &str, rt: &tokio::runtime::Runtime) {
    use vox_core::cbor::Decoder;
    use vox_core::group::message::GroupMessage;
    use vox_core::log::entry::Entry;
    use vox_core::node::drive::drive_channel;

    let tmp = root.join("legacy-session-copies");
    std::fs::create_dir(&tmp).expect("APPARATUS: legacy Session scratch directory");
    let mut r = rt.block_on(room::room_as(
        &tmp,
        &["owner", "current", "revoked", "reader"],
        old,
    ));
    let session = "legacy-upgrade-session";
    let first = "LEGACY-BEFORE-REVOCATION";
    let second = "LEGACY-AFTER-REVOCATION";
    let new = "PRIVATE-AFTER-UPGRADE-REVOCATION";
    let hook = |w: &room::Worker, text: &str, side: &str| {
        let transcript = tmp.join("session.jsonl");
        std::fs::write(&transcript, "").expect("APPARATUS: scratch Session transcript");
        let payload = serde_json::json!({
            "session_id": session, "transcript_path": transcript, "cwd": tmp,
            "permission_mode": "default", "hook_event_name": "UserPromptSubmit",
            "prompt": text, "prompt_id": text,
        })
        .to_string();
        let node = w.paths.account().nodes_on_disk()[0].clone();
        let o = w.vox_env(
            None,
            &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
            &["agent", "hook", "--node", node.as_str(), "--room", &r.id],
            Some(&payload),
        );
        assert!(o.ok, "{side}: Session hook failed: {o:?}");
    };
    let history = |w: &room::Worker| {
        w.vox(
            None,
            &["room", "session", &r.id, session, "--details", "--json"],
        )
    };
    let wait_old_history = |w: &room::Worker, wanted: &[&str]| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let o = history(w);
            if o.ok && wanted.iter().all(|text| o.stdout.contains(text)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: published {} did not stage its readable Session steps: {o:?}",
                w.name
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    };
    for i in [1, 2] {
        let o = r.workers[0].vox(
            None,
            &[
                "trust",
                "drive",
                &r.workers[i].b32(),
                "--identity-passphrase-file",
                r.workers[0].pass.to_str().unwrap(),
            ],
        );
        assert!(
            o.ok,
            "APPARATUS: published owner could not grant drive: {o:?}"
        );
    }
    hook(&r.workers[0], first, "APPARATUS");
    for i in [1, 2] {
        wait_old_history(&r.workers[i], &[first]);
    }
    let o = r.workers[0].vox(
        None,
        &[
            "trust",
            "read",
            &r.workers[2].b32(),
            "--identity-passphrase-file",
            r.workers[0].pass.to_str().unwrap(),
        ],
    );
    assert!(
        o.ok,
        "APPARATUS: published owner could not revoke drive: {o:?}"
    );
    hook(&r.workers[0], second, "APPARATUS");
    wait_old_history(&r.workers[1], &[first, second]);
    let control = "ORDINARY-CHAT-AFTER-OLD-STEPS";
    let o = r.workers[0].vox(None, &["room", "post", &r.id, control]);
    assert!(
        o.ok,
        "APPARATUS: published ordinary control post failed: {o:?}"
    );
    for w in &r.workers[1..] {
        await_upgrade_post(w, &r.id, control);
    }
    let o = history(&r.workers[2]);
    assert!(
        o.ok && o.stdout.contains(first) && !o.stdout.contains(second),
        "APPARATUS: old revoked driver must hold only its earlier readable step: {o:?}"
    );

    let before = session_copies_as_owner(&mut r, rt, false);
    let legacy: Vec<BTreeMap<_, _>> = before
        .iter()
        .map(|copies| {
            copies
                .public
                .iter()
                .filter(|entry| {
                    entry
                        .payload
                        .as_deref()
                        .and_then(|p| GroupMessage::from_wire(p).ok())
                        .is_some_and(|m| m.header.channel_id == drive_channel(&r.cid))
                })
                .map(|entry| (entry.entry_hash(), entry.to_wire()))
                .collect()
        })
        .collect();
    assert!(
        legacy[0].len() >= 2 && !legacy[1].is_empty(),
        "APPARATUS: original author did not recover staged ciphertext from both legacy drivers"
    );
    println!(
        "[proof] published holders served original author {} / {} / {} legacy encrypted records",
        legacy[0].len(),
        legacy[1].len(),
        legacy[2].len()
    );
    r.upgrade(VOX);
    for w in &r.workers {
        await_upgrade_post(w, &r.id, control);
    }
    for i in [0, 1] {
        let o = r.workers[i].vox(
            None,
            &["room", "session", &r.id, session, "--details", "--json"],
        );
        assert!(
            o.ok && o.stdout.contains(first) && o.stdout.contains(second),
            "PRODUCT: {} lost authorized legacy Session history: {o:?}",
            r.workers[i].name
        );
    }
    for i in [2, 3] {
        let o = r.workers[i].vox(
            None,
            &["room", "session", &r.id, session, "--details", "--json"],
        );
        assert!(
            o.ok && !o.stdout.contains(first) && !o.stdout.contains(second),
            "PRODUCT: {} retained forbidden legacy Session cache: {o:?}",
            r.workers[i].name
        );
    }

    for restart in [false, true] {
        if restart {
            // After migration, losing drive must preserve the history already read. A new
            // step and an ordinary later post make absence of the new private step measurable.
            let o = r.workers[0].vox(
                None,
                &[
                    "trust",
                    "read",
                    &r.workers[1].b32(),
                    "--identity-passphrase-file",
                    r.workers[0].pass.to_str().unwrap(),
                ],
            );
            assert!(
                o.ok,
                "PRODUCT: owner could not revoke current driver: {o:?}"
            );
            let transcript = tmp.join("session.jsonl");
            let node = r.workers[0].paths.account().nodes_on_disk()[0].clone();
            let payload = serde_json::json!({"session_id": session, "transcript_path": transcript,
                "cwd": tmp, "permission_mode": "default", "hook_event_name": "UserPromptSubmit",
                "prompt": new, "prompt_id": new})
            .to_string();
            let o = r.workers[0].vox_env(
                None,
                &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
                &["agent", "hook", "--node", node.as_str(), "--room", &r.id],
                Some(&payload),
            );
            assert!(o.ok, "PRODUCT: post-upgrade Session hook failed: {o:?}");
            let o = r.workers[0].vox(None, &["room", "post", &r.id, "ORDINARY-AFTER-NEW-REVOKE"]);
            assert!(o.ok, "PRODUCT: post-upgrade control post failed: {o:?}");
            for w in &r.workers[1..] {
                await_upgrade_post(w, &r.id, "ORDINARY-AFTER-NEW-REVOKE");
            }
            r.upgrade(VOX);
        }
        let after = session_copies_as_owner(&mut r, rt, true);
        // A read-only old member held only skeletons, so it needs the upgraded author's
        // declaration before those placeholders can be classified. The wire-copy checks
        // above did not wait for this: migration must precede service publication.
        let online = format!("MIGRATED-OWNER-ONLINE-{restart}");
        let o = r.workers[0].vox(None, &["room", "post", &r.id, &online]);
        assert!(
            o.ok,
            "PRODUCT: upgraded owner could not post its live control: {o:?}"
        );
        for w in &r.workers[1..] {
            await_upgrade_post(w, &r.id, &online);
        }
        for (i, copies) in after.iter().enumerate() {
            for hash in legacy[i].keys() {
                let entry = copies
                    .public
                    .iter()
                    .find(|e| e.entry_hash() == *hash)
                    .expect("PRODUCT: migration lost a signed public skeleton");
                assert!(entry.payload.is_none(),
                    "PRODUCT: {} still served legacy Session ciphertext publicly, restart={restart}",
                    r.workers[i + 1].name);
            }
            if i != 0 {
                assert!(copies.private.is_empty(),
                    "PRODUCT: {} retained {} private Session copies without drive at upgrade, restart={restart}",
                    r.workers[i + 1].name, copies.private.len());
            } else {
                let migrated: BTreeMap<_, _> = copies
                    .private
                    .iter()
                    .filter_map(|wire| {
                        let mut d = Decoder::new(wire);
                        if d.array().ok()? != 2 || d.uint().ok()? != 2 {
                            return None;
                        }
                        let original = d.bytes().ok()?.to_vec();
                        let entry = Entry::from_wire(&original).ok()?;
                        Some((entry.entry_hash(), original))
                    })
                    .collect();
                for (hash, wire) in &legacy[0] {
                    assert_eq!(migrated.get(hash), Some(wire),
                        "PRODUCT: current driver did not preserve original signed legacy record privately, restart={restart}");
                }
            }
            let w = &r.workers[i + 1];
            let o = room::until(
                w,
                None,
                "upgraded author's Session declarations in General",
                &["room", "read", &r.id, "--limit", "1000"],
                |o| o.ok && o.stdout.contains(&online) && !o.stdout.contains("not received yet"),
            );
            assert!(o.ok && o.stdout.contains(control) && !o.stdout.contains("not received yet")
                && !o.stdout.contains(first) && !o.stdout.contains(second) && !o.stdout.contains(new),
                "PRODUCT: {}'s General lost ordinary chat or exposed private activity/placeholder: {o:?}", w.name);
            let o = w.vox(
                None,
                &["room", "session", &r.id, session, "--details", "--json"],
            );
            assert!(
                o.ok && o.stdout.contains(first) == (i == 0)
                    && o.stdout.contains(second) == (i == 0)
                    && !o.stdout.contains(new),
                "PRODUCT: {}'s retained Session history changed, restart={restart}: {o:?}",
                w.name
            );
        }
        println!("[proof] legacy encrypted copies removed from public sync; private originals only at authorized migration holder; restart={restart}");
    }
}
