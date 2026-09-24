//! ADR-021 M21.8 — **the zero-operator rehearsal**: two live-model workers do work
//! through Vox while a stub tracker, which lives only in this proof, records it — and
//! **observations never become completion verdicts**.
//!
//! The stub tracker applies the external tracker's own rules
//! (`agent-work-accountability`, `references/work-model.md` and
//! `synchronization-contract.md`) to what it consumes through the ADR-021 adapter
//! surfaces — `vox room tail --since --json` and `vox room board --json` — and to
//! nothing else. It is deliberately not in the product: Vox has no tracker, no work
//! phase and no GitHub, and must not grow one (ADR-021 §1).
//!
//! The work is done by **two real OpenCode sessions** on two nodes, each running `vox`
//! through its own shell. Nobody else runs a Vox command that participates: the proof
//! only starts model turns, and the tracker only posts `assign`.
//!
//! What it asserts, each at the checkpoint where it can first be true:
//!
//! 0. **a claim is ownership, not work** — after a claim the item is owned and still
//!    Ready, with no attempt; **`working` starts the attempt** and moves it to Executing,
//!    and the attempt's id is the one Vox seeded from the claim;
//! 1. **`blocked` never changes Work phase** — the item stays Executing and only its
//!    Health becomes Blocked;
//! 2. **a failed attempt leaves the item retryable** — Ready again, with the failed
//!    attempt kept in its history — and **a retry exists only from its `working`**: a
//!    re-claim, a `status` and even a `result` before it start nothing, and that early
//!    `result` stays an assertion;
//! 3. **a worker killed mid-attempt** loses the item only by its lease lapsing, and the
//!    item is retryable, not failed and not done;
//! 4. **`result` reaches Acceptance at most** — never Release ready, never Done;
//! 5. **`release` never means Done** — the accepted-candidate item stays in Acceptance
//!    after its owner releases it;
//! 6. **the tracker can be absent**: it is stopped while workers keep claiming and
//!    posting (Vox does not notice), then resumes from its persisted cursor and misses
//!    nothing;
//! 7. **zero operator commands**: every work observation in the room was written by a
//!    model's own session (its `from` is an OpenCode session id), and every `assign` by
//!    the tracker.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeMap;
use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{until, Out, Worker, HARNESS_SESSION_VARS, VOX};

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}
fn auth_present() -> bool {
    std::env::var_os("HOME").is_some_and(|h| {
        Path::new(&h)
            .join(".local/share/opencode/auth.json")
            .is_file()
    })
}
fn model() -> String {
    std::env::var("VOX_PROOF_OPENCODE_MODEL")
        .unwrap_or_else(|_| "opencode/claude-haiku-4-5".to_owned())
}

// ------------------------------------------------------------------ the stub tracker

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Executing,
    Acceptance,
    ReleaseReady,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    OnTrack,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Attempt {
    id: String,
    session: String,
    /// The `working` entry that started it — the attempt-start evidence.
    start: String,
    outcome: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct Item {
    phase: Phase,
    health: Health,
    owner: Option<(String, String)>,
    attempts: Vec<Attempt>,
    candidate: Option<String>,
    /// `result`s seen with no attempt-start observation: assertions, never phase changes.
    unstarted_results: usize,
    /// Every phase this item has ever been in — so "never Done" is checked over the
    /// whole history, not just the end.
    history: Vec<Phase>,
}

/// The tracker: it owns the items and their phases; Vox only supplies observations.
struct Tracker {
    items: BTreeMap<String, Item>,
    cursor: Option<String>,
    rows_seen: usize,
}

impl Tracker {
    fn new(refs: &[&str]) -> Self {
        let items = refs
            .iter()
            .map(|r| {
                // Ready is the TRACKER's fact (design approved), recorded here — never
                // derived from anything in the room.
                (
                    (*r).to_owned(),
                    Item {
                        phase: Phase::Ready,
                        health: Health::OnTrack,
                        owner: None,
                        attempts: vec![],
                        candidate: None,
                        unstarted_results: 0,
                        history: vec![Phase::Ready],
                    },
                )
            })
            .collect();
        Self {
            items,
            cursor: None,
            rows_seen: 0,
        }
    }

    fn set(item: &mut Item, p: Phase) {
        if item.phase != p {
            item.phase = p;
            item.history.push(p);
        }
    }

    /// Apply one `vox.room.row/1` observation, per the tracker's event-to-state rules.
    fn observe(&mut self, row: &serde_json::Value) {
        assert_eq!(
            row["schema"], "vox.room.row/1",
            "the adapter refuses any other schema"
        );
        self.cursor = row["entry_hash"].as_str().map(str::to_owned);
        self.rows_seen += 1;
        if row["op"]["status"] == "conflict" || row["op"]["status"] == "duplicate" {
            return; // a void or repeated operation is not an observation
        }
        let env = &row["envelope"];
        let Some(work) = env["data"]["work"].as_str() else {
            return;
        };
        let Some(item) = self.items.get_mut(work) else {
            return;
        };
        let session = env["from"].as_str().unwrap_or("").to_owned();
        let attempt = env["data"]["attempt"].as_str().unwrap_or("").to_owned();
        let entry = row["entry_hash"].as_str().unwrap_or("").to_owned();
        let active = |item: &Item| {
            item.attempts
                .iter()
                .position(|a| a.id == attempt && a.outcome.is_none())
        };
        match env["type"].as_str().unwrap_or("") {
            // Only `working` starts an attempt; its entry is the start evidence. A later
            // `working` with the same id continues it. A work-key-bound attempt start
            // moves Ready to Executing.
            "working" => {
                if active(item).is_none() {
                    item.attempts.push(Attempt {
                        id: attempt,
                        session,
                        start: entry,
                        outcome: None,
                    });
                }
                item.health = Health::OnTrack;
                if item.phase == Phase::Ready {
                    Self::set(item, Phase::Executing);
                }
            }
            // A blocker changes Health and leaves Work phase unchanged.
            "blocked" => item.health = Health::Blocked,
            // A result naming an immutable candidate moves Executing to Acceptance —
            // only for an attempt whose `working` was observed, and no further: Release
            // ready needs an independent verdict this tracker never receives from Vox.
            "result" => match (active(item), env["data"]["evidence"][0]["ref"].as_str()) {
                (Some(i), Some(c)) if item.phase == Phase::Executing => {
                    item.candidate = Some(c.to_owned());
                    item.attempts[i].outcome = Some("submitted");
                    item.health = Health::OnTrack;
                    Self::set(item, Phase::Acceptance);
                }
                _ => item.unstarted_results += 1,
            },
            // A failed attempt ends; the item stays retryable. A retry does not exist
            // until its own `working`.
            "failed" => {
                if let Some(i) = active(item) {
                    item.attempts[i].outcome = Some("work failure");
                    item.health = Health::OnTrack;
                    if item.phase == Phase::Executing {
                        Self::set(item, Phase::Ready);
                    }
                }
            }
            // claim, renew, accept, status: ownership or notes — never an attempt.
            _ => {}
        }
    }

    /// Record ownership from `board --json` — never reconstructed from claim messages.
    /// An attempt whose owner is gone without a `result` or `failed` has ended by
    /// release or expiry; the item is retryable.
    fn board(&mut self, board: &serde_json::Value) {
        assert_ne!(
            board["coordination"], "refused",
            "the adapter records no owner under a refusal"
        );
        for (work, item) in &mut self.items {
            let held = board["resources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["resource"] == *work && r["state"] == "held");
            item.owner = held.map(|h| {
                (
                    h["owner_fp"].as_str().unwrap().to_owned(),
                    h["owner_session"].as_str().unwrap().to_owned(),
                )
            });
            if item.owner.is_none() && item.phase == Phase::Executing {
                if let Some(a) = item.attempts.iter_mut().rev().find(|a| a.outcome.is_none()) {
                    a.outcome = Some("expired or released");
                }
                Self::set(item, Phase::Ready);
            }
        }
    }

    fn never_past_acceptance(&self) {
        for (k, item) in &self.items {
            assert!(
                !item.history.contains(&Phase::ReleaseReady)
                    && !item.history.contains(&Phase::Done),
                "{k}: an observation moved an item past Acceptance: {:?}",
                item.history
            );
        }
    }
}

/// The adapter: `vox room tail --since <cursor> --json` on one node, feeding the tracker.
struct Adapter {
    child: std::process::Child,
    rx: std::sync::mpsc::Receiver<serde_json::Value>,
}

impl Adapter {
    fn start(w: &Worker, r: &str, cursor: &str) -> Self {
        let mut cmd = Command::new(VOX);
        cmd.args(["room", "tail", r, "--since", cursor, "--json"])
            .env("VOX_DATA_DIR", &w.data)
            .env("VOX_CONFIG_DIR", &w.cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for v in HARNESS_SESSION_VARS {
            cmd.env_remove(v);
        }
        let mut child = cmd.spawn().expect("tail");
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(serde_json::from_str(&l).expect("row")).is_err() {
                    return;
                }
            }
        });
        Self { child, rx }
    }
    fn pump(&self, t: &mut Tracker) {
        while let Ok(row) = self.rx.recv_timeout(Duration::from_secs(3)) {
            t.observe(&row);
        }
    }
    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------ the workers

struct Agent<'a> {
    worker: &'a Worker,
    name: &'static str,
    project: PathBuf,
    session: Option<String>,
}

impl Agent<'_> {
    /// One real model turn, continuing this agent's own session after the first.
    fn turn(
        &mut self,
        oc_cfg: &Path,
        bin_dir: &Path,
        room: &str,
        prompt: &str,
        kill_after: Option<Duration>,
    ) -> String {
        let mut cmd = Command::new("opencode");
        cmd.env_clear();
        for key in ["HOME", "SHELL", "LANG", "TMPDIR", "USER"] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let mut args = vec!["run".to_owned(), "--auto".into(), "-m".into(), model()];

        if let Some(s) = &self.session {
            args.push("--session".into());
            args.push(s.clone());
        }
        args.push(prompt.to_owned());
        cmd.current_dir(&self.project)
            .args(&args)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("XDG_CONFIG_HOME", oc_cfg)
            .env("VOX_DATA_DIR", &self.worker.data)
            .env("VOX_CONFIG_DIR", &self.worker.cfg)
            .env("VOX_ROOM", room)
            .env("VOX_AGENT_NAME", self.name)
            .env("VOX_BIN", VOX)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("opencode");
        // Every turn has a deadline of its own, so a turn that never returns is reported
        // as exactly that — with its output — rather than surfacing as the whole-process
        // watchdog, which says only that something, somewhere, hung.
        let deadline = std::time::Instant::now() + kill_after.unwrap_or(Duration::from_secs(240));
        while child.try_wait().ok().flatten().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let timed_out = child.try_wait().ok().flatten().is_none();
        if timed_out {
            let _ = child.kill(); // the worker dies mid-attempt, or the turn overran
        }
        let out = child.wait_with_output().unwrap();
        if timed_out && kill_after.is_none() {
            eprintln!(
                "[receipt] {} turn TIMED OUT after 240 s and was killed",
                self.name
            );
        }
        let s = format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("[receipt] {} turn {prompt:?}\n{s}", self.name);
        s
    }
}

fn instructions(steps: &[&str]) -> String {
    format!(
        "You are a worker in a shared Vox room ($VOX_ROOM). Use your shell to run each of \
         these commands exactly, in order, substituting nothing except where told, and then \
         reply DONE:\n{}",
        steps
            .iter()
            .map(|s| format!("  {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
#[ignore = "two nodes, production Argon2id, and live model turns; CI runs it in release"]
fn workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict() {
    watchdog::arm();
    if which("opencode").is_none() || !auth_present() {
        assert!(allow_unproven("opencode"), "UNPROVEN: the rehearsal needs `opencode` and a credential. Set VOX_PROOF_ALLOW_UNPROVEN=opencode to accept that gap deliberately.");
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.clone();

    let fixture = std::env::temp_dir().join("vox-tracker-rehearsal");
    let oc_cfg = fixture.join("config");
    let bin_dir = fixture.join("bin");
    std::fs::create_dir_all(oc_cfg.join("opencode")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    let _ = std::fs::remove_file(bin_dir.join("vox"));
    std::os::unix::fs::symlink(VOX, bin_dir.join("vox")).unwrap();
    let mut agents = Vec::new();
    for (w, name) in [(alice, "w1"), (bob, "w2")] {
        let project = fixture.join(name);
        std::fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
        let plugin = project.join(".opencode/plugin/vox.js");
        // The mutation control: without the Vox plugin the room never reaches the model and
        // the model's shells carry no session, so the rehearsal must fail — or it was
        // measuring something other than Vox. (`opencode run --pure` was the first choice,
        // and hung the warm-up turn for its whole deadline with `--auto`, which would make a
        // red nobody can attribute.)
        if std::env::var_os("VOX_PROOF_WITHOUT_PLUGIN").is_some() {
            let _ = std::fs::remove_file(&plugin);
        } else {
            std::fs::write(&plugin, vox_tui::agent_hook::OPENCODE_PLUGIN).unwrap();
        }
        agents.push(Agent {
            worker: w,
            name,
            project,
            session: None,
        });
    }
    for a in &mut agents {
        let _ = a.turn(&oc_cfg, &bin_dir, &r, "Reply with exactly: READY", None);
        // warm
    }

    // ---- the tracker mints two references and assigns them — its only posts ----
    let (item1, item2) = ("wl:rehearsal#1", "wl:rehearsal#2");
    let mut tracker = Tracker::new(&[item1, item2]);
    let start = bob
        .vox(None, &["room", "read", &r, "--json"])
        .ndjson()
        .last()
        .map(|x| x["entry_hash"].as_str().unwrap().to_owned());
    for (item, to) in [(item1, "w1"), (item2, "w2")] {
        let o = bob.vox_in(
            Some("tracker"),
            &[
                "room",
                "post",
                &r,
                "--type",
                "assign",
                "--work",
                item,
                "--to",
                to,
                "--op",
                &format!("op-assign-{}", item.replace([':', '#'], "-")),
                "-",
            ],
            Some(&format!("please take {item}")),
        );
        assert!(o.ok, "the tracker could not assign: {o:?}");
    }
    until(
        alice,
        None,
        "the assignments to reach alice",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains(item2),
    );
    let start = start.unwrap_or_else(|| {
        bob.vox(None, &["room", "read", &r, "--json"]).ndjson()[0]["entry_hash"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    let adapter = Adapter::start(bob, &r, &start);

    // w1 takes item 1 — ownership only.
    let (w1, w2) = agents.split_at_mut(1);
    let (w1, w2) = (&mut w1[0], &mut w2[0]);
    let _ = w1.turn(
        &oc_cfg,
        &bin_dir,
        &r,
        &instructions(&["vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#1' --ttl 45"]),
        None,
    );
    let w1_session = until(
        bob,
        None,
        "w1's claim to reach the tracker's node",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), item1).is_some(),
    )
    .json();
    w1.session = support::resource(&w1_session, item1)
        .and_then(|x| x["owner_session"].as_str())
        .map(str::to_owned);
    assert!(
        w1.session.as_deref().is_some_and(|s| s.starts_with("ses")),
        "w1's claim must carry its OpenCode session: {w1_session}"
    );
    let w1_acquisition = support::resource(&w1_session, item1).unwrap()["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    adapter.pump(&mut tracker);
    tracker.board(&w1_session);
    // ---- (0) a claim is ownership, not work ----
    let i1 = &tracker.items[item1];
    assert!(
        i1.owner.is_some(),
        "the claim must give w1 ownership: {i1:?}"
    );
    assert_eq!(
        i1.phase,
        Phase::Ready,
        "a claim must leave the item Ready: {i1:?}"
    );
    assert!(
        i1.attempts.is_empty(),
        "a claim must start no attempt: {i1:?}"
    );

    // w1 starts its attempt — `working`, with the id Vox seeds.
    let _ = w1.turn(
        &oc_cfg,
        &bin_dir,
        &r,
        &instructions(&[
            "vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#1' starting",
        ]),
        None,
    );
    until(
        bob,
        None,
        "w1's working",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains("starting"),
    );
    adapter.pump(&mut tracker);
    let i1 = &tracker.items[item1];
    assert_eq!(
        i1.phase,
        Phase::Executing,
        "`working` must start the attempt: {i1:?}"
    );
    assert_eq!(
        i1.attempts
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        [w1_acquisition.as_str()],
        "the attempt's id must be the one Vox seeded from the claim: {i1:?}"
    );
    assert!(!i1.attempts[0].start.is_empty(), "{i1:?}");

    // w2 takes item 2, starts, and is blocked.
    let _ = w2.turn(&oc_cfg, &bin_dir, &r, &instructions(&[
        "vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#2' --ttl 600",
        "vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#2' starting",
        "vox room post \"$VOX_ROOM\" --type blocked --work 'wl:rehearsal#2' --data '{\"reason\":\"waiting on the schema\"}' blocked",
    ]), None);
    let b = until(
        bob,
        None,
        "w2's claim",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), item2).is_some(),
    )
    .json();
    w2.session = support::resource(&b, item2)
        .and_then(|x| x["owner_session"].as_str())
        .map(str::to_owned);
    until(
        bob,
        None,
        "w2's blocked",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains("waiting on the schema"),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());

    // ---- (1) blocked never changes Work phase ----
    let i2 = &tracker.items[item2];
    assert_eq!(i2.phase, Phase::Executing, "{i2:?}");
    assert_eq!(i2.health, Health::Blocked, "{i2:?}");
    assert_eq!(tracker.items[item1].phase, Phase::Executing);
    eprintln!("[proof] checkpoint 1: {:?}", tracker.items);

    // ---- (6) the tracker goes away; work continues ----
    let resume = tracker.cursor.clone().unwrap();
    adapter.stop();
    let _ = w2.turn(&oc_cfg, &bin_dir, &r, &instructions(&[
        "vox room post \"$VOX_ROOM\" --type failed --work 'wl:rehearsal#2' --data '{\"reason\":\"the schema never came\"}' giving-up",
        "vox room release \"$VOX_ROOM\" 'wl:rehearsal#2'",
    ]), None);
    // (3) w1 dies mid-attempt: its turn is killed and it never renews.
    let _ = w1.turn(
        &oc_cfg,
        &bin_dir,
        &r,
        &instructions(&["sleep 300"]),
        Some(Duration::from_secs(8)),
    );
    until(
        bob,
        None,
        "w2's failure while the tracker is down",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains("the schema never came"),
    );
    std::thread::sleep(Duration::from_secs(45)); // w1's 45 s lease lapses with nobody acting

    // The tracker comes back, from its persisted cursor.
    let adapter = Adapter::start(bob, &r, &resume);
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    let (i1, i2) = (&tracker.items[item1], &tracker.items[item2]);
    // ---- (2) failed leaves the item retryable ----
    assert_eq!(
        i2.phase,
        Phase::Ready,
        "a failed attempt must leave the item retryable: {i2:?}"
    );
    assert_eq!(
        i2.attempts.first().and_then(|a| a.outcome),
        Some("work failure"),
        "{i2:?}"
    );
    assert!(i2.owner.is_none(), "{i2:?}");
    // ---- (3) the killed worker's item is retryable, not failed, not done ----
    assert_eq!(i1.phase, Phase::Ready, "{i1:?}");
    assert_eq!(
        i1.attempts.first().and_then(|a| a.outcome),
        Some("expired or released"),
        "{i1:?}"
    );
    eprintln!(
        "[proof] checkpoint 2 (after the tracker's absence): {:?}",
        tracker.items
    );

    // ---- (2, continued) a retry exists only from its `working` ----
    // w2 re-claims, notes progress and even asserts a result — none of which starts an
    // attempt.
    let _ = w2.turn(&oc_cfg, &bin_dir, &r, &instructions(&[
        "vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#2' --ttl 600",
        "vox room post \"$VOX_ROOM\" --type status --work 'wl:rehearsal#2' looking-again",
        "vox room post \"$VOX_ROOM\" --type result --work 'wl:rehearsal#2' --data '{\"evidence\":[{\"kind\":\"commit\",\"ref\":\"1111aaaa\"}]}' premature",
    ]), None);
    until(
        bob,
        None,
        "w2's premature result",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains("1111aaaa"),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    let i2 = &tracker.items[item2];
    assert!(i2.owner.is_some(), "{i2:?}");
    assert_eq!(
        i2.phase,
        Phase::Ready,
        "re-claim, status and an unstarted result must leave it Ready: {i2:?}"
    );
    assert_eq!(
        i2.attempts.len(),
        1,
        "no retry exists before its `working`: {i2:?}"
    );
    assert_eq!(
        i2.candidate, None,
        "an unstarted result is an assertion, not a candidate: {i2:?}"
    );
    assert_eq!(i2.unstarted_results, 1, "{i2:?}");

    // ---- (4) the retry starts, and submits a candidate: Acceptance at most ----
    let _ = w2.turn(&oc_cfg, &bin_dir, &r, &instructions(&[
        "vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#2' retrying",
        "vox room post \"$VOX_ROOM\" --type result --work 'wl:rehearsal#2' --data '{\"evidence\":[{\"kind\":\"commit\",\"ref\":\"9f3c2e1a\"}]}' candidate-ready",
    ]), None);
    until(
        bob,
        None,
        "w2's result",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains("9f3c2e1a"),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    assert_eq!(
        tracker.items[item2].phase,
        Phase::Acceptance,
        "{:?}",
        tracker.items[item2]
    );
    assert_eq!(tracker.items[item2].candidate.as_deref(), Some("9f3c2e1a"));
    let i2 = &tracker.items[item2];
    assert_eq!(
        i2.attempts.len(),
        2,
        "the retry is a second attempt: {i2:?}"
    );
    assert_ne!(
        i2.attempts[0].id, i2.attempts[1].id,
        "a retry has its own id: {i2:?}"
    );

    // ---- (5) release never means Done ----
    let _ = w2.turn(
        &oc_cfg,
        &bin_dir,
        &r,
        &instructions(&["vox room release \"$VOX_ROOM\" 'wl:rehearsal#2'"]),
        None,
    );
    until(
        bob,
        None,
        "w2's release",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), item2).is_none(),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    assert_eq!(
        tracker.items[item2].phase,
        Phase::Acceptance,
        "release must not mean Done: {:?}",
        tracker.items[item2]
    );
    tracker.never_past_acceptance();
    adapter.stop();
    eprintln!("[proof] final: {:?}", tracker.items);

    // ---- (7) zero operator commands ----
    let rows = bob.vox(None, &["room", "read", &r, "--json"]).ndjson();
    let sessions: Vec<String> = [w1.session.clone(), w2.session.clone()]
        .into_iter()
        .flatten()
        .collect();
    for row in rows.iter().filter(|x| {
        x["envelope"]["data"]["work"].is_string() || x["envelope"]["data"]["resource"].is_string()
    }) {
        let (kind, from) = (
            row["envelope"]["type"].as_str().unwrap(),
            row["envelope"]["from"].as_str().unwrap_or(""),
        );
        if kind == "assign" {
            assert_eq!(from, "tracker", "only the tracker assigns: {row}");
        } else {
            assert!(
                sessions.iter().any(|s| s == from),
                "a work observation not written by a model's own session: {row}"
            );
        }
    }
    assert!(tracker.rows_seen > 0);
}
