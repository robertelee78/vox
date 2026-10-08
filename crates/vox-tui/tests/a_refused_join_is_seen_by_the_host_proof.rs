//! #406 — **a join a host refuses is seen by that host's operator**, and never carries the
//! joiner's secret, through the shipped binary: a real `vox daemon` (and the real `vox tui`) as the
//! host, and a real joiner turned away for a wrong room passphrase.
//!
//! A host refusing a join is security-relevant: someone holding the room's address tried a
//! passphrase that is not the room's. Under ADR-026 the join is answered in the host's daemon, so
//! that is where it must be said: on the daemon's stderr when it runs in the foreground, in
//! `<data root>/.daemon/log` when a client started it, and in the TUI's notice line when a person
//! watches the TUI. The node words it from what it knows — the joiner and the step that failed
//! (`answering <joiner>: join proof-of-possession failed`) — and the passphrase it was offered is
//! nowhere in it.
//!
//! **Arms** (each a wrong-passphrase `vox room join` by bob, which is refused):
//! - **foreground:** alice's `vox daemon`, run by hand: its stderr says the join did not complete,
//!   names bob, and does not hold the wrong passphrase;
//! - **auto-started:** alice's daemon started by `vox node attach` (detached): `.daemon/log` says
//!   the same;
//! - **TUI:** alice's `vox tui`, attached to the node the foreground daemon holds: its notice line
//!   says the join did not complete (`tests/pty/tui_watch_notice.py`).
//!
//! Every red names its side: `PRODUCT:` what the host said or did not; `PRODUCT (staging):` a `vox`
//! step of the staging (a join that was not refused); `APPARATUS:` the driver's own machinery.
//!
//! - **decision record** (ADR-028 §7, #506, #563): alice's node records the foreground arm's
//!   refusal as one event naming bob, why, and the room by its ID (never its name), read through
//!   her daemon as her clients read it; the record is sealed at rest in
//!   `nodes/default/decisions/<today>.sealed` (0600, its directory 0700), so neither bob's
//!   fingerprint, the passphrase bob offered, nor a message alice posted is readable in any of its
//!   files. Two earlier days are planted before her daemon starts as an earlier build wrote them,
//!   in the clear (`<day>.jsonl`): the one 14 days old is removed, and the one 13 days old is
//!   sealed into its day's file, its plain file removed, and its event still read back. `vox status` names that refusal under "recent refusals", and first in
//!   `--json`'s `refusals`; alice's TUI, on `d`, shows both refusals of bob's join (the
//!   foreground arm's and the TUI arm's), newest first (D-3, #507).
//!
//! **Mutations that must turn it red:** the daemon's per-node reporter no longer saying a
//! `JoinFailed` (`tunnel_cli::say_if_it_explains_a_failure`) — the foreground and auto-started arms
//! red; the TUI ignoring `JoinFailed` (`DaemonCore::on_node_event`) — the TUI arm red; a node
//! that records a message's text in its decision record when it posts one — the record arm red;
//! the record written in the clear again — the record arm red (#563);
//! a join refusal recorded with no room — the record arm red; a status report with no refusals in
//! it — the `vox status` claims red; the TUI's decision record read oldest first — the TUI's
//! decision claim red.

#![cfg(unix)]

#[path = "support/decision_record.rs"]
mod decision_record;
#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOM_PASS: &str = "the room's own passphrase";
/// What bob offers instead: unique enough that finding it anywhere is finding the leak.
const WRONG: &str = "QXJZ-a-wrong-room-passphrase-KVWY";
/// How long the host has to say it, once bob has been told no.
const SAYS_WITHIN: Duration = Duration::from_secs(10);
const SAID: &str = "a join did not complete — answering ";
/// Whom the planted earlier days' events name: a fingerprint as `vox` prints one.
const PLANTED_BY: &str = "plantedplantedplantedplantedplantedplantedplantedpla";
/// A message alice posts in her room: found in her decision record, it is the leak (ADR-028 D-2).
const MESSAGE: &str = "QXJZ-a-message-nobody-records-KVWY";

/// A child process, stopped by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One person's data root, with the files a verb reads passphrases from.
struct Person {
    dir: PathBuf,
    fp: String,
}

fn cmd(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(VOX);
    c.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_NODE");
    c
}

fn run(dir: &Path, args: &[&str]) -> (bool, String) {
    let o = cmd(dir, args)
        .output()
        .expect("APPARATUS: could not run vox");
    (
        o.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

fn file(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, format!("{text}\n")).expect("APPARATUS: could not write a staging file");
    p.to_str()
        .expect("APPARATUS: a temp path is not UTF-8")
        .to_owned()
}

impl Person {
    fn new(root: &Path, name: &str) -> Self {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: could not make a directory");
        let pass = file(&dir, "id.pass", IDENTITY);
        let (ok, said) = run(&dir, &["id", "--identity-passphrase-file", &pass]);
        let fp = said
            .split_whitespace()
            .find(|w| w.len() == 52)
            .unwrap_or_default()
            .to_owned();
        assert!(
            ok && !fp.is_empty(),
            "PRODUCT (staging): {name}'s `vox id`: {said}"
        );
        Self { dir, fp }
    }

    fn pass(&self) -> String {
        self.dir
            .join("id.pass")
            .to_str()
            .expect("APPARATUS: a temp path is not UTF-8")
            .to_owned()
    }

    /// Attach the node by hand (starting a detached daemon if none runs).
    fn attach(&self) {
        let (ok, said) = run(
            &self.dir,
            &[
                "node",
                "attach",
                "default",
                "--passphrase-file",
                &self.pass(),
            ],
        );
        assert!(ok, "PRODUCT (staging): `vox node attach`: {said}");
    }

    /// A room, and an room link to it.
    fn room(&self) -> String {
        let rp = file(&self.dir, "room.pass", ROOM_PASS);
        let (ok, said) = run(
            &self.dir,
            &["room", "create", "--name", "home", "--passphrase-file", &rp],
        );
        assert!(ok, "PRODUCT (staging): `vox room create`: {said}");
        let (_, list) = run(&self.dir, &["room", "list"]);
        let id = list
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let (ok, link) = run(&self.dir, &["room", "link", &id]);
        assert!(ok, "PRODUCT (staging): `vox room link`: {link}");
        link.lines()
            .find(|l| l.starts_with("vox://"))
            .unwrap_or_else(|| panic!("PRODUCT (staging): no link in {link:?}"))
            .to_owned()
    }
}

/// `vox daemon` run by hand for `p`, its stderr to `err`; once it answers.
fn foreground_daemon(p: &Person, err: &Path) -> Proc {
    let child = cmd(
        &p.dir,
        &[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &p.pass(),
        ],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(std::fs::File::create(err).expect("APPARATUS: could not make a log file"))
    .spawn()
    .expect("APPARATUS: could not start vox daemon");
    let daemon = Proc(child);
    let t0 = Instant::now();
    while !run(&p.dir, &["node", "list"])
        .1
        .contains("default attached")
    {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): alice's daemon never attached her node: {}",
            std::fs::read_to_string(err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    daemon
}

/// Bob tries `link` with a wrong passphrase: refused, or a staging red.
fn wrong_join(bob: &Person, link: &str) {
    let wp = file(&bob.dir, "wrong.pass", WRONG);
    let (ok, said) = run(&bob.dir, &["room", "join", "--passphrase-file", &wp, link]);
    assert!(
        !ok,
        "PRODUCT (staging): bob's join with a wrong passphrase was not refused: {said}"
    );
}

/// How long ago a row of the TUI's decision record says it was decided, in seconds:
/// `<n><unit> ago …`, its first word.
fn age_secs(row: &str) -> Option<u64> {
    let word = row.split_whitespace().next()?;
    let (n, unit) = word.split_at(word.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = n.parse().ok()?;
    Some(match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3_600,
        "d" => n * 86_400,
        _ => return None,
    })
}

/// Wait up to [`SAYS_WITHIN`] for `log` to say the join was refused; what it holds then.
fn says(log: impl Fn() -> String) -> String {
    let t0 = Instant::now();
    loop {
        let text = log();
        if text.contains(SAID) || t0.elapsed() >= SAYS_WITHIN {
            return text;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The verdict on what the host said in `where_`.
fn judge(red: &mut Vec<String>, where_: &str, text: &str, bob: &Person) {
    let short: String = bob.fp.chars().take(12).collect();
    let line = text.lines().find(|l| l.contains(SAID)).unwrap_or("");
    println!("[proof] {where_}: {line:?}");
    if line.is_empty() || !line.contains(&short) {
        red.push(format!(
            "PRODUCT: {where_} does not say the host refused bob's join (wanted {SAID:?} \
             naming {short}): {text:?}"
        ));
    }
    if text.contains(WRONG) {
        red.push(format!(
            "PRODUCT: {where_} holds the passphrase bob offered: {text:?}"
        ));
    }
}

#[test]
#[ignore = "real vox daemons and vox tui in a pty, a real join refused; needs pyte (VOX_PYTE_PATH)"]
fn a_refused_join_is_seen_by_the_host() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let bob = Person::new(tmp.path(), "bob");
    bob.attach();
    let mut red = Vec::new();

    // ---- foreground: alice's `vox daemon`, run by hand ----------------------------------------
    let alice = Person::new(tmp.path(), "alice");
    // Two days of an earlier record: one 14 days old, past what is kept, and one 13 days old.
    let record = decision_record::dir(&alice.dir, "default");
    std::fs::create_dir_all(&record).expect("APPARATUS: could not make the record's directory");
    std::fs::set_permissions(&record, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("APPARATUS: could not set the record directory's mode");
    let today = decision_record::today();
    let (old, kept) = (
        format!("{}.jsonl", decision_record::date_of(today - 14)),
        format!("{}.jsonl", decision_record::date_of(today - 13)),
    );
    // As an earlier build wrote a day: one event per line, in the clear.
    let planted = |days_ago: i64| {
        let at_ms = u64::try_from((today - days_ago) * 86_400_000 + 3_600_000).unwrap_or(0);
        format!(
            "{}\n",
            serde_json::json!({ "at_ms": at_ms, "asked": "a tunnel to a service",
                "by": PLANTED_BY, "alias": null, "decided": "refused",
                "why": format!("planted {days_ago} days ago") })
        )
    };
    for (name, days_ago) in [(&old, 14), (&kept, 13)] {
        std::fs::write(record.join(name), planted(days_ago))
            .expect("APPARATUS: could not plant an earlier day's record");
    }
    let err = tmp.path().join("alice.daemon.err");
    let _alice_daemon = foreground_daemon(&alice, &err);
    let link = alice.room();
    let (_, list) = run(&alice.dir, &["room", "list"]);
    let room_id = list
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let (ok, said) = run(&alice.dir, &["room", "post", &room_id, MESSAGE]);
    assert!(ok, "PRODUCT (staging): alice's `vox room post`: {said}");
    wrong_join(&bob, &link);
    let said = says(|| std::fs::read_to_string(&err).unwrap_or_default());
    judge(&mut red, "alice's foreground daemon's stderr", &said, &bob);

    // ---- the decision record (ADR-028 §7, #506): alice's node keeps what it refused --------
    let (events, _) = decision_record::until(&alice.dir, "default", SAYS_WITHIN, |e| {
        decision_record::is(e, "to join a room", "refused", &bob.fp)
    });
    let refusals = events
        .iter()
        .filter(|e| decision_record::is(e, "to join a room", "refused", &bob.fp))
        .count();
    println!("[proof] alice's decision record: {events:?}");
    if refusals != 1 {
        red.push(format!(
            "PRODUCT: alice's decision record must hold one refused join naming bob ({}) and why; \
             it holds {refusals}: {events:?}",
            bob.fp
        ));
    }
    // The room it concerns, by its ID and nothing else of it (ADR-028 D-1, D-2): M-18's room
    // filter reads it.
    let refusal = events
        .iter()
        .find(|e| decision_record::is(e, "to join a room", "refused", &bob.fp));
    // `vox room list` shows the ID's first characters; the event holds it whole.
    let named = refusal.and_then(|e| e["room"].as_str()).unwrap_or_default();
    if named.len() != vox_core::node::link::B32_DIGEST_LEN
        || !named.starts_with(room_id.as_str())
        || refusal.is_some_and(|e| e.to_string().contains("\"home\""))
    {
        red.push(format!(
            "PRODUCT: the refused join's event must name the room by its whole ID ({room_id}…), \
             and not by its name \"home\": {refusal:?}"
        ));
    }
    let files = decision_record::files(&alice.dir, "default");
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    let sealed = |n: &str| n.replace(".jsonl", ".sealed");
    let today_file = format!("{}.sealed", decision_record::date_of(today));
    let kept_read = events
        .iter()
        .any(|e| e["why"] == "planted 13 days ago" && e["by"] == PLANTED_BY);
    let old_read = events.iter().any(|e| e["why"] == "planted 14 days ago");
    println!("[proof] alice's decision record files: {names:?}");
    if names.contains(&old.as_str())
        || names.contains(&sealed(&old).as_str())
        || old_read
        || names.contains(&kept.as_str())
        || !names.contains(&sealed(&kept).as_str())
        || !kept_read
        || !names.contains(&today_file.as_str())
    {
        red.push(format!(
            "PRODUCT: alice's decision record must keep 14 days, sealed: {kept}'s event sealed into \
             {} and still read back (read: {kept_read}), its plain file gone; {today_file} \
             written; {old} removed (read: {old_read}); it holds {names:?}",
            sealed(&kept)
        ));
    }
    for (text, what) in [
        (WRONG, "the passphrase bob offered"),
        (MESSAGE, "the text of a message"),
        (bob.fp.as_str(), "bob's fingerprint, in the clear"),
        (PLANTED_BY, "an earlier build's event, in the clear"),
        ("to join a room", "an event's words, in the clear"),
    ] {
        if files.iter().any(|(_, t)| t.contains(text)) {
            red.push(format!(
                "PRODUCT: alice's decision record holds {what}: {files:?}"
            ));
        }
    }
    // `vox status` names the refusal (ADR-028 D-3, #507): as a person reads it, and in --json.
    let short: String = bob.fp.chars().take(12).collect();
    let (ok, status) = run(&alice.dir, &["status"]);
    let line = status
        .lines()
        .skip_while(|l| l.trim() != "recent refusals")
        .nth(1)
        .unwrap_or("")
        .to_owned();
    println!("[proof] alice's `vox status`, its newest refusal: {line:?}");
    let named = line.contains(&format!("refused {short} to join a room:"));
    if !ok || !named || !line.contains("answering") {
        red.push(format!(
            "PRODUCT: alice's `vox status` must name her refusal of bob's join under \
             \"recent refusals\"; it said: {status}"
        ));
    }
    let (ok, json) = run(&alice.dir, &["status", "--json"]);
    let newest = serde_json::from_str::<serde_json::Value>(json.trim())
        .ok()
        .map(|v| v["refusals"][0].clone());
    if !ok
        || newest.as_ref().is_none_or(|e| {
            e["by"] != bob.fp.as_str() || e["asked"] != "to join a room" || !e["why"].is_string()
        })
    {
        red.push(format!(
            "PRODUCT: alice's `vox status --json` must name her refusal of bob's join first in \
             `refusals`; it said: {json}"
        ));
    }
    let mode = |p: &Path| {
        std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(p)
                .map(|m| m.permissions())
                .unwrap_or_else(|e| {
                    panic!(
                        "PRODUCT: alice's decision record has no {}: {e}",
                        p.display()
                    )
                }),
        ) & 0o777
    };
    let (dir_mode, file_mode) = (mode(&record), mode(&record.join(&today_file)));
    if (dir_mode, file_mode) != (0o700, 0o600) {
        red.push(format!(
            "PRODUCT: alice's decision record must be hers alone: the directory {dir_mode:o} \
             (0700), today's file {file_mode:o} (0600)"
        ));
    }

    // ---- TUI: alice's `vox tui`, on the node that daemon holds --------------------------------
    let cues = tmp.path().join("cues");
    std::fs::create_dir_all(&cues).expect("APPARATUS: could not make a directory");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_watch_notice.py");
    let args: Vec<String> = vec![
        VOX.to_owned(),
        alice.dir.to_string_lossy().into_owned(),
        alice.dir.join("cfg").to_string_lossy().into_owned(),
        cues.to_string_lossy().into_owned(),
        "a join did not complete".to_owned(),
        "alice".to_owned(),
    ];
    let driver = std::thread::spawn(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        pty_driver::run(script, &args)
    });
    let t0 = Instant::now();
    while !cues.join("ready").exists() && t0.elapsed() < Duration::from_secs(90) {
        std::thread::sleep(Duration::from_millis(100));
    }
    if cues.join("ready").exists() {
        wrong_join(&bob, &link);
    }
    let out = driver
        .join()
        .expect("APPARATUS: the TUI driver thread panicked");
    match out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("alice SAID: "))
    {
        Some(screen) => {
            judge(&mut red, "alice's TUI's notice line", screen, &bob);
            // Her TUI's decision record, newest first (ADR-028 D-3, #507): the join it just
            // refused, then the one her foreground daemon refused before it.
            let rows: Vec<&str> = out
                .stdout
                .lines()
                .filter_map(|l| l.strip_prefix("alice DECISION: "))
                .collect();
            println!("[proof] alice's TUI's decision record: {rows:?}");
            let short: String = bob.fp.chars().take(12).collect();
            let joins: Vec<u64> = rows
                .iter()
                .filter(|r| r.contains(&format!("refused {short}: to join a room")))
                .filter_map(|r| age_secs(r))
                .collect();
            if joins.len() != 2 || joins[0] > joins[1] {
                red.push(format!(
                    "PRODUCT: alice's TUI must show her two refusals of bob's join, newest first; \
                     its decision record shows: {rows:#?}"
                ));
            }
        }
        None => red.push(format!(
            "{}: alice's TUI driver did not read its screen (exit {:?}): {}",
            if out.has_verdict("alice") && !out.stdout.contains("alice APPARATUS") {
                "PRODUCT (staging)"
            } else {
                "APPARATUS"
            },
            out.code,
            out.stdout
        )),
    }

    // ---- auto-started: carol's daemon, started by `vox node attach` ---------------------------
    let carol = Person::new(tmp.path(), "carol");
    carol.attach();
    let link = carol.room();
    wrong_join(&bob, &link);
    let log = carol.dir.join(".daemon").join("log");
    let said = says(|| std::fs::read_to_string(&log).unwrap_or_default());
    judge(
        &mut red,
        "carol's auto-started daemon's .daemon/log",
        &said,
        &bob,
    );
    // The detached daemons stop when told; by pid, from their locks.
    for p in [&bob, &carol] {
        if let Some(pid) = std::fs::read_to_string(p.dir.join(".daemon").join("lock"))
            .ok()
            .and_then(|t| t.split_whitespace().next().map(str::to_owned))
        {
            let _ = Command::new("kill").args(["-TERM", &pid]).status();
        }
    }
    assert!(red.is_empty(), "{red:#?}");
}
