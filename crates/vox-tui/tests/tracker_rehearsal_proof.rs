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
//!
//! **Points 4 and 5 are the stub tracker's own rules, not product proofs.** Vox has no
//! phase: what it contributes there is the typed `result` row and the board after a
//! `release`, which the other checkpoints already prove. Never moving past Acceptance is
//! the stub's `observe` and `board` applying the tracker's rules, so a red there is the
//! APPARATUS (the stub), and nothing Vox does can turn it red or green. They stay because
//! the rehearsal shows the tracker's rules holding on Vox's real rows, not as a claim.
//!
//! Every red names its side. Each model turn's `vox` commands are recorded with how `vox`
//! answered (`support::model_shim`): a step the model never ran is CANNOT MEASURE (the
//! apparatus); a step `vox` refused is PRODUCT, quoting the refusal; and a step `vox`
//! accepted that never arrives is PRODUCT. Each step that a checkpoint judges runs in its
//! own turn when an earlier step's failure would otherwise hide it — w2's `blocked` follows
//! its claim and `working` in a separate turn, so a product that drops ownership on
//! `blocked` is caught at checkpoint 1, not as a claim that never arrived.

// Optional (decider, 2026-10-01): it needs a live model, so it blocks nothing and CI only
// compiles it. Without `--features optional-proofs` a stand-in takes its place and says it was not
// run (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict
);

#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeMap;
use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{Out, Worker, VOX};

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}
fn model() -> String {
    oc_sandbox::model()
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
            "PRODUCT: the adapter refuses any other schema"
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
            "PRODUCT: the adapter records no owner under a refusal"
        );
        for (work, item) in &mut self.items {
            let held = board["resources"]
                .as_array()
                .expect("PRODUCT: vox room board's JSON has no resources list")
                .iter()
                .find(|r| r["resource"] == *work && r["state"] == "held");
            item.owner = held.map(|h| {
                (
                    h["owner_fp"].as_str().expect("PRODUCT: a held resource in vox room board's JSON has no owner_fp").to_owned(),
                    h["owner_session"].as_str().expect("PRODUCT: a held resource in vox room board's JSON has no owner_session").to_owned(),
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
                "APPARATUS (the stub tracker's own rule, not a product proof): {k}: an \
                 observation moved an item past Acceptance: {:?}",
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
        support::strip_harness_env(&mut cmd);
        let mut child = cmd.spawn().expect("APPARATUS: tail");
        let out = child
            .stdout
            .take()
            .expect("APPARATUS: a piped stdio handle");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                if tx
                    .send(serde_json::from_str(&l).expect("PRODUCT: row"))
                    .is_err()
                {
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
    /// The sandbox every turn of this agent runs in, and its profile (support/oc_sandbox.rs).
    sb: &'a oc_sandbox::OcSandbox,
    profile: PathBuf,
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
        // Confined, with a fixed environment (`OcSandbox::opencode`): the recording `vox` shim
        // first on the model's PATH, then the system's.
        let mut cmd = self.sb.opencode(&self.profile, &[bin_dir], &self.project);
        let mut args = vec!["run".to_owned(), "--auto".into(), "-m".into(), model()];

        if let Some(s) = &self.session {
            args.push("--session".into());
            args.push(s.clone());
        }
        args.push(prompt.to_owned());
        cmd.args(&args)
            .env("XDG_CONFIG_HOME", oc_cfg)
            .env("VOX_DATA_DIR", &self.worker.data)
            .env("VOX_CONFIG_DIR", &self.worker.cfg)
            .env("VOX_ROOM", room)
            .env("VOX_AGENT_NAME", self.name)
            .env("VOX_BIN", VOX)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run opencode in its sandbox: {e}"));
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
        let out = child
            .wait_with_output()
            .expect("APPARATUS: wait for a child process");
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
        self.sb.check(&s, "an `opencode run` turn");
        eprintln!("[receipt] {} turn {prompt:?}\n{s}", self.name);
        s
    }
}

impl Agent<'_> {
    /// One model turn running `steps`, each judged from what its shell ran: a step `vox`
    /// refused is a PRODUCT red quoting the refusal; a step the model never ran is CANNOT
    /// MEASURE, with the model's reply.
    fn run(&mut self, oc_cfg: &Path, bin_dir: &Path, calls: &Path, room: &str, steps: &[&str]) {
        let _ = std::fs::write(calls, "");
        let reply = self.turn(oc_cfg, bin_dir, room, &instructions(steps), None);
        for step in steps {
            let words: Vec<String> = step
                .split_whitespace()
                .map(|w| w.trim_matches('\'').to_owned())
                .collect();
            let mut needles = vec![format!("room {}", words[2])];
            if let Some(i) = words.iter().position(|w| w == "--type") {
                needles.push(format!("--type {}", words[i + 1]));
            }
            needles.extend(words.iter().filter(|w| w.starts_with("wl:")).cloned());
            let ran = support::vox_accepted(calls, self.name, &format!("`{step}`"), |a| {
                needles.iter().all(|n| a.contains(n.as_str()))
            });
            assert!(
                ran,
                "CANNOT MEASURE (apparatus, not product): {} never ran `{step}` — nothing \
                 reached `vox`. Its shell ran: {:?}. Its reply:\n{reply}",
                self.name,
                support::model_calls(calls)
                    .iter()
                    .map(|c| c.args.as_str())
                    .collect::<Vec<_>>()
            );
        }
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

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two nodes, production Argon2id, and live model turns; optional, run it in release"]
fn workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict() {
    watchdog::arm();
    if !oc_sandbox::live_model_allowed(
        "tracker_rehearsal_proof::workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict",
    ) {
        return;
    }
    assert!(
        which("opencode").is_some(),
        "APPARATUS, CANNOT MEASURE: the rehearsal needs `opencode` on PATH"
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: start a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.clone();

    // **Every model turn runs confined** (support/oc_sandbox.rs): a throwaway HOME, a fixed
    // environment, a whitelist of readable paths, a canary in the real HOME it must never see.
    // The plugins' hooks and the models' `vox` need the two workers' vox profiles; nothing
    // else outside the sandbox is readable. A missing credential is CANNOT MEASURE there.
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    let profile = sb.profile(
        "tracker",
        &[&alice.data, &alice.cfg, &bob.data, &bob.cfg],
        &[Path::new(VOX)],
    );
    // **This run's own fixture, inside its sandbox**: two trees sharing one fixture ran each
    // other's `vox` (as the drain proof's); OpenCode installs into it on the warm-up turn.
    let fixture = sb.root.join("fixture");
    let oc_cfg = fixture.join("config");
    let bin_dir = fixture.join("bin");
    std::fs::create_dir_all(oc_cfg.join("opencode"))
        .expect("APPARATUS: create a staging directory");
    std::fs::create_dir_all(&bin_dir).expect("APPARATUS: create a staging directory");
    let calls = fixture.join("model-shell-calls.log");
    support::model_shim(&bin_dir, &calls);
    let mut agents = Vec::new();
    for (w, name) in [(alice, "w1"), (bob, "w2")] {
        let project = fixture.join(name);
        std::fs::create_dir_all(project.join(".opencode/plugin"))
            .expect("APPARATUS: create a staging directory");
        let plugin = project.join(".opencode/plugin/vox.js");
        // The mutation control: without the Vox plugin the room never reaches the model and
        // the model's shells carry no session, so the rehearsal must fail — or it was
        // measuring something other than Vox. (`opencode run --pure` was the first choice,
        // and hung the warm-up turn for its whole deadline with `--auto`, which would make a
        // red nobody can attribute.)
        if std::env::var_os("VOX_PROOF_WITHOUT_PLUGIN").is_some() {
            let _ = std::fs::remove_file(&plugin);
        } else {
            std::fs::write(
                &plugin,
                vox_tui::agent_hook::opencode_plugin(
                    &vox_core::node::paths::NodeName::parse("default")
                        .expect("APPARATUS: the node name"),
                ),
            )
            .expect("APPARATUS: write a staging file");
        }
        agents.push(Agent {
            worker: w,
            sb: &sb,
            profile: profile.clone(),
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
        .map(|x| {
            x["entry_hash"]
                .as_str()
                .expect("PRODUCT: a row of vox room read --json has no entry_hash")
                .to_owned()
        });
    // Each worker is addressed by its node, as `--to` takes it (a member's fingerprint, or the
    // reader's own name for it), not by its agent name: w1 runs on alice's node, w2 on bob's.
    let (w1_node, w2_node) = (alice.b32(), bob.b32());
    for (item, to) in [(item1, w1_node.as_str()), (item2, w2_node.as_str())] {
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
        assert!(o.ok, "PRODUCT: the tracker could not assign: {o:?}");
    }
    support::arrives(
        alice,
        "the assignments to reach alice",
        &["room", "read", &r],
        |o: &Out| o.stdout.contains(item2),
    );
    let start = start.unwrap_or_else(|| {
        bob.vox(None, &["room", "read", &r, "--json"]).ndjson()[0]["entry_hash"]
            .as_str()
            .expect("PRODUCT: a row of vox room read --json has no entry_hash")
            .to_owned()
    });
    let adapter = Adapter::start(bob, &r, &start);

    // w1 takes item 1 — ownership only.
    let (w1, w2) = agents.split_at_mut(1);
    let (w1, w2) = (&mut w1[0], &mut w2[0]);
    w1.run(
        &oc_cfg,
        &bin_dir,
        &calls,
        &r,
        &["vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#1' --ttl 45"],
    );
    let w1_session = support::arrives(
        bob,
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
        "PRODUCT: w1's claim must carry its OpenCode session: {w1_session}"
    );
    let w1_acquisition = support::resource(&w1_session, item1)
        .expect("PRODUCT: the board names no resource for w1's item")["acquisition"]
        .as_str()
        .expect("PRODUCT: w1's resource has no acquisition")
        .to_owned();
    adapter.pump(&mut tracker);
    tracker.board(&w1_session);
    // ---- (0) a claim is ownership, not work ----
    let i1 = &tracker.items[item1];
    assert!(
        i1.owner.is_some(),
        "PRODUCT: the claim must give w1 ownership: {i1:?}"
    );
    assert_eq!(
        i1.phase,
        Phase::Ready,
        "PRODUCT: a claim must leave the item Ready: {i1:?}"
    );
    assert!(
        i1.attempts.is_empty(),
        "PRODUCT: a claim must start no attempt: {i1:?}"
    );

    // w1 starts its attempt — `working`, with the id Vox seeds.
    w1.run(
        &oc_cfg,
        &bin_dir,
        &calls,
        &r,
        &["vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#1' starting"],
    );
    support::arrives(bob, "w1's working", &["room", "read", &r], |o: &Out| {
        o.stdout.contains("starting")
    });
    adapter.pump(&mut tracker);
    let i1 = &tracker.items[item1];
    assert_eq!(
        i1.phase,
        Phase::Executing,
        "PRODUCT: `working` must start the attempt: {i1:?}"
    );
    assert_eq!(
        i1.attempts
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        [w1_acquisition.as_str()],
        "PRODUCT: the attempt's id must be the one Vox seeded from the claim: {i1:?}"
    );
    assert!(
        !i1.attempts[0].start.is_empty(),
        "PRODUCT: the `working` row carries no entry hash: {i1:?}"
    );

    // w2 takes item 2 and starts — and only then, in a turn of its own, is blocked: a
    // product that drops ownership on `blocked` must be caught at checkpoint 1, and with all
    // three in one turn it showed only as a claim that never reached the board.
    w2.run(
        &oc_cfg,
        &bin_dir,
        &calls,
        &r,
        &[
            "vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#2' --ttl 600",
            "vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#2' starting",
        ],
    );
    let b = support::arrives(
        bob,
        "w2's claim to reach the tracker's node",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), item2).is_some(),
    )
    .json();
    w2.session = support::resource(&b, item2)
        .and_then(|x| x["owner_session"].as_str())
        .map(str::to_owned);
    w2.run(&oc_cfg, &bin_dir, &calls, &r, &[
        "vox room post \"$VOX_ROOM\" --type blocked --work 'wl:rehearsal#2' --data '{\"reason\":\"waiting on the schema\"}' blocked",
    ]);
    // The reason is in the row's data, which `--json` carries and the words do not (#406).
    support::arrives(
        bob,
        "w2's blocked",
        &["room", "read", &r, "--json"],
        |o: &Out| o.stdout.contains("waiting on the schema"),
    );
    adapter.pump(&mut tracker);
    let board = bob.vox(None, &["room", "board", &r, "--json"]).json();
    tracker.board(&board);

    // ---- (1) blocked never changes Work phase ----
    let i2 = &tracker.items[item2];
    assert_eq!(
        i2.phase,
        Phase::Executing,
        "PRODUCT: `blocked` changed Work phase — w2 held {item2} and had started it before \
         `blocked`, and after it the board no longer shows it held: {i2:?}\nboard: {board}"
    );
    assert_eq!(
        i2.health,
        Health::Blocked,
        "PRODUCT: w2's `blocked` row did not reach the tracker as a blocker on {item2}: {i2:?}"
    );
    assert_eq!(
        tracker.items[item1].phase,
        Phase::Executing,
        "PRODUCT: w1's started item left Executing with nothing but w2's work in between: {:?}",
        tracker.items[item1]
    );
    eprintln!("[proof] checkpoint 1: {:?}", tracker.items);

    // ---- (6) the tracker goes away; work continues ----
    let resume = tracker
        .cursor
        .clone()
        .expect("APPARATUS: the tracker kept a cursor");
    adapter.stop();
    w2.run(&oc_cfg, &bin_dir, &calls, &r, &[
        "vox room post \"$VOX_ROOM\" --type failed --work 'wl:rehearsal#2' --data '{\"reason\":\"the schema never came\"}' giving-up",
        "vox room release \"$VOX_ROOM\" 'wl:rehearsal#2'",
    ]);
    // (3) w1 dies mid-attempt: its turn is killed and it never renews.
    let _ = w1.turn(
        &oc_cfg,
        &bin_dir,
        &r,
        &instructions(&["sleep 300"]),
        Some(Duration::from_secs(8)),
    );
    support::arrives(
        bob,
        "w2's failure while the tracker is down",
        // The reason is in the row's data, which `--json` carries and the words do not (#406).
        &["room", "read", &r, "--json"],
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
        "PRODUCT: a failed attempt must leave the item retryable: {i2:?}"
    );
    assert_eq!(
        i2.attempts.first().and_then(|a| a.outcome),
        Some("work failure"),
        "PRODUCT: w2's `failed` row, read from the resumed cursor, did not end its attempt: \
         {i2:?}"
    );
    assert!(
        i2.owner.is_none(),
        "PRODUCT: w2's release left it holding {item2}: {i2:?}"
    );
    // ---- (3) the killed worker's item is retryable, not failed, not done ----
    assert_eq!(
        i1.phase,
        Phase::Ready,
        "PRODUCT: the killed worker's lapsed lease did not leave {item1} retryable: {i1:?}"
    );
    assert_eq!(
        i1.attempts.first().and_then(|a| a.outcome),
        Some("expired or released"),
        "PRODUCT: the killed worker's attempt ended other than by its lease: {i1:?}"
    );
    eprintln!(
        "[proof] checkpoint 2 (after the tracker's absence): {:?}",
        tracker.items
    );

    // ---- (2, continued) a retry exists only from its `working` ----
    // w2 re-claims, notes progress and even asserts a result — none of which starts an
    // attempt.
    w2.run(&oc_cfg, &bin_dir, &calls, &r, &[
        "vox room claim \"$VOX_ROOM\" --work 'wl:rehearsal#2' --ttl 600",
        "vox room post \"$VOX_ROOM\" --type status --work 'wl:rehearsal#2' looking-again",
        "vox room post \"$VOX_ROOM\" --type result --work 'wl:rehearsal#2' --data '{\"evidence\":[{\"kind\":\"commit\",\"ref\":\"1111aaaa\"}]}' premature",
    ]);
    support::arrives(
        bob,
        "w2's premature result",
        // The evidence ref is in the row's data, which `--json` carries and the words do not (#406).
        &["room", "read", &r, "--json"],
        |o: &Out| o.stdout.contains("1111aaaa"),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    let i2 = &tracker.items[item2];
    assert!(
        i2.owner.is_some(),
        "PRODUCT: w2's re-claim did not give it {item2}: {i2:?}"
    );
    assert_eq!(
        i2.phase,
        Phase::Ready,
        "PRODUCT: re-claim, status and an unstarted result must leave it Ready: {i2:?}"
    );
    assert_eq!(
        i2.attempts.len(),
        1,
        "PRODUCT: no retry exists before its `working`: {i2:?}"
    );
    assert_eq!(
        i2.candidate, None,
        "PRODUCT: an unstarted result is an assertion, not a candidate: {i2:?}"
    );
    assert_eq!(
        i2.unstarted_results, 1,
        "PRODUCT: the premature `result` row did not reach the tracker: {i2:?}"
    );

    // ---- (4) the retry starts, and submits a candidate: Acceptance at most ----
    w2.run(&oc_cfg, &bin_dir, &calls, &r, &[
        "vox room post \"$VOX_ROOM\" --type working --work 'wl:rehearsal#2' retrying",
        "vox room post \"$VOX_ROOM\" --type result --work 'wl:rehearsal#2' --data '{\"evidence\":[{\"kind\":\"commit\",\"ref\":\"9f3c2e1a\"}]}' candidate-ready",
    ]);
    support::arrives(
        bob,
        "w2's result",
        &["room", "read", &r, "--json"],
        |o: &Out| o.stdout.contains("9f3c2e1a"),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    // Reaching Acceptance rests on Vox's typed `result` row (the started attempt's id and
    // its evidence ref): PRODUCT. Going no further is the stub's own rule (see the module
    // note), checked by `never_past_acceptance`.
    assert_eq!(
        tracker.items[item2].phase,
        Phase::Acceptance,
        "PRODUCT: the retry's `result` row did not reach the tracker as the started attempt's \
         result with its evidence: {:?}",
        tracker.items[item2]
    );
    assert_eq!(
        tracker.items[item2].candidate.as_deref(),
        Some("9f3c2e1a"),
        "PRODUCT: the `result` row lost its evidence ref"
    );
    let i2 = &tracker.items[item2];
    assert_eq!(
        i2.attempts.len(),
        2,
        "PRODUCT: the retry is a second attempt: {i2:?}"
    );
    assert_ne!(
        i2.attempts[0].id, i2.attempts[1].id,
        "PRODUCT: a retry has its own id: {i2:?}"
    );

    // ---- (5) release never means Done ----
    w2.run(
        &oc_cfg,
        &bin_dir,
        &calls,
        &r,
        &["vox room release \"$VOX_ROOM\" 'wl:rehearsal#2'"],
    );
    support::arrives(
        bob,
        "w2's release",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), item2).is_none(),
    );
    adapter.pump(&mut tracker);
    tracker.board(&bob.vox(None, &["room", "board", &r, "--json"]).json());
    assert_eq!(
        tracker.items[item2].phase,
        Phase::Acceptance,
        "APPARATUS (the stub tracker's own rule, not a product proof): its `board` treated a \
         release as Done: {:?}",
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
            row["envelope"]["type"]
                .as_str()
                .expect("PRODUCT: a row of vox room read --json has no envelope type"),
            row["envelope"]["from"].as_str().unwrap_or(""),
        );
        if kind == "assign" {
            assert_eq!(from, "tracker", "PRODUCT: only the tracker assigns: {row}");
        } else {
            assert!(
                sessions.iter().any(|s| s == from),
                "PRODUCT: a work observation not written by a model's own session: {row}"
            );
        }
    }
    assert!(
        tracker.rows_seen > 0,
        "PRODUCT: `vox room tail --since --json` emitted no row"
    );
}
