//! **A fresh user gets from install to an agent working in a room** (v0.4.3): the whole journey a
//! person takes, scripted, against the shipped binaries. It is an optional heavy proof
//! (docs/release/optional-proofs.md): it blocks no CI run, and it is run before every release tag.
//!
//! The decider, 2026-10-10: "as much as I love having the Quality engineering around the
//! Application, we neglected to test the rest of the journey". Every proof before this one starts
//! from a world it staged: nodes made, rooms joined, trust given. On the first real agent setup the
//! decider hit, in order: the skill missing after an update; setup offering one node name, y/n
//! only; an empty passphrase refused; raw hook JSON to merge by hand; nodes detached after every
//! restart, with only the agent told; no prompt for the repo's room; a Session that could not be
//! found; a rename not shown. Each of those is a handoff between two commands, and only a journey
//! sees a handoff.
//!
//! ## The world
//!
//! One scratch root: a `HOME` holding no node, no keychain item of Vox's and no Vox wiring in any
//! harness's settings; a data root and config directory in it (`VOX_DATA_DIR`, `VOX_CONFIG_DIR`,
//! never the operator's); a stand-in for `/Applications` (`VOX_APPLICATIONS_DIR`); and the three
//! real harnesses (Claude Code, Codex, OpenCode) on `PATH`, as installed here. Of each harness's
//! own configuration the root holds only what a person who already uses it has: its model provider
//! (the stand-in model, `support/model_standin.py`, on loopback) and, for Claude Code, its
//! onboarding done and the repo trusted. No model runs: every harness turn runs confined by
//! `oc_sandbox::offline_profile`, with no network but the stand-in's port and the run's own Unix
//! sockets, after a canary in the real HOME has been probed unreadable.
//!
//! ## The journey, and its checks
//!
//! Each check is a claim with an id; a run reports every claim, so one run lists every red.
//! A step the product failed is answered the way a person would get past it (an empty passphrase
//! refused: the person types one), and the rest of the journey is still measured.
//!
//! 1. **Install** from the built artifacts the way `install.sh` does: the real script, from a
//!    loopback release of this build (`J1.install`); the agent skill pack is then where each
//!    harness on `PATH` reads it (`J1.pack`). `vox update` from v0.4.2 is not measured: the
//!    published v0.4.2 fetches only from github.com, and no loopback release can serve it.
//! 2. **`vox setup`** at a terminal, answered as a person: a node name of the person's own for each
//!    harness (`J2.names`), an empty passphrase (`J2.empty_passphrase`, ruled optional
//!    2026-10-10), yes to a node for the person. Each harness is wired by setup itself, with no
//!    JSON to merge by hand (`J2.wired`); every node it made is attached (`J2.attached`).
//! 3. A stub **repo**; the person makes a room on their own node.
//! 4. **Each harness started in the repo**: its session says what is missing and the one command
//!    (`J4.<harness>.one_command`). The person runs only that, and starts a new session, until the
//!    session reaches the room (`J4.<harness>.reaches_room`). Vox asks the person, not only the
//!    model, for the repo's room (`J4.<harness>.person_asked`); the person binds it, and the next
//!    session works in the room (`J4.<harness>.bound`).
//! 5. **Trust**: the person's node is offered each agent's node (`J5.offered.<harness>`); the
//!    person and each agent trust each other, and the person is granted drive (`J5.trust.<harness>`).
//! 6. **The agent posts** from its own shell; the person reads it (`J6.<harness>.read`) and finds
//!    its Session (`J6.<harness>.listed`). An interactive Claude Code in a terminal is found open
//!    (`J6.drive.found`), driven by the person while idle (`J6.drive.said`: the typed line reaches
//!    the harness's model), and renamed from Vox, the new name shown (`J6.drive.renamed`). Driven
//!    while it waits on an approval, the line reaches its model or is refused with the reason,
//!    never said delivered and lost (`J6.drive.while_waiting`).
//! 7. **The daemon restarts**, then **`vox update`** runs: every node is still attached
//!    (`J7.restart.attached`, `J7.update.attached`), the skill pack and the hooks are still in
//!    place (`J7.update.pack`, `J7.update.hooks`), the update asked for nothing (`J7.update.ok`),
//!    and each harness's next session works in the room with nothing retyped
//!    (`J7.<harness>.ready`).
//! 8. **Every flow-ending command's last lines name the next action** (`J8.<command>`): install,
//!    setup, each command a session named, the room join, the trust grants, the update.
//! 9. **Every hook path answers in under 1 s with one sentence of guidance**: node detached, no
//!    daemon, no node (`J9.<path>.fast`, `J9.<path>.one_sentence`), for Claude Code's and Codex's
//!    wiring as setup wrote it.
//!
//! ## Which side a red is on
//!
//! `PRODUCT` quotes what a `vox` command, a hook or a harness session printed. `APPARATUS` is this
//! proof's own staging failing (a file, a process, the sandbox, the stand-in model, a harness that
//! did not finish a turn). `CANNOT MEASURE (precondition unmet)` is a check whose earlier step the
//! product failed, so it could not be asked; it is listed, and the run is not green.
//!
//! ## Mutants
//!
//! Each claim names the product change that turns it red on its own assertion; the status of each
//! is in `~/vox-coord/journey-proof-status.md`.
//!
//! - `J1.install`: install.sh's final `vox --version` check removed and the served asset swapped
//!   for another version's → red. `J1.pack`: `shell-setup` not running `skill --install` → red.
//! - `J2.names`: `node_name` ignoring what is typed → red. `J2.empty_passphrase`: the
//!   `first.is_empty()` refusal in `ask_new_passphrase` kept → red (today). `J2.wired`:
//!   `Wiring::install` writing no hook → red. `J2.attached`: setup making nodes without attaching
//!   them → red (today).
//! - `J4.*.one_command`: `vox agent status` printing two commands → red. `J4.*.reaches_room`:
//!   status naming `vox node attach` for an attached node → red (loops). `J4.*.person_asked`: the
//!   ask given to the model only → red (today). `J4.*.bound`: `--bind` not writing the room map → red.
//! - `J5.offered.*`: offers listing only room joiners → red. `J5.trust.*`: `trust add --drive`
//!   granting read only → red.
//! - `J6.*.read`: the hook's node not posting as itself → red. `J6.*.listed`: `room sessions`
//!   dropping ended sessions → red. `J6.drive.said`: drive handed to no pane → red.
//!   `J6.drive.renamed`: a driven `/rename` not recorded (#669 reverted) → red.
//!   `J6.drive.while_waiting`: red today (the driven Enter approved the pending command, and the
//!   text was lost, while Vox said "delivered to its terminal").
//! - `J7.*`: the daemon not re-attaching kept nodes at start → red (today); `vox update` skipping
//!   the skill refresh when nothing is newer (the v0.4.2 defect) → `J7.update.pack` red;
//!   `vox update` not re-wiring hooks → `J7.update.hooks` red.
//! - `J8.*`: a command's closing "next" line removed → red.
//! - `J9.*.fast`: a hook that waits on the daemon's start → red; `J9.*.one_sentence`: the
//!   detached-node guidance as two sentences → red (today).

#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_fresh_user_gets_from_install_to_an_agent_working_in_a_room);

#[cfg(feature = "optional-proofs")]
#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[cfg(feature = "optional-proofs")]
#[allow(dead_code)]
#[path = "support/release_server.rs"]
mod release_server;

#[cfg(feature = "optional-proofs")]
#[path = "support/test_knobs.rs"]
mod test_knobs;

#[cfg(feature = "optional-proofs")]
mod journey {
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{oc_sandbox, release_server, test_knobs, watchdog};

    pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
    /// What the person answers each passphrase question with first: nothing (ruled optional,
    /// 2026-10-10).
    const EMPTY: &str = "";
    const ROOM: &str = "journey";
    const ROOM_PASS: &str = "journey room passphrase";
    const PERSON: &str = "robin";

    /// The harnesses, as `vox` names them, as a person names them, and the node name the person
    /// types for each instead of the one setup offers.
    pub const HARNESSES: [(&str, &str, &str); 3] = [
        ("claude", "Claude Code", "claude-mine"),
        ("codex", "Codex", "codex-mine"),
        ("opencode", "OpenCode", "opencode-mine"),
    ];

    // ------------------------------------------------------------------------------- the ledger

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Verdict {
        Pass,
        Product,
        Apparatus,
        CannotMeasure,
    }

    /// Every claim the journey asked, in order, with its verdict and what was seen.
    #[derive(Default)]
    pub struct Ledger(Vec<(String, Verdict, String)>);

    impl Ledger {
        /// `ok`, or a PRODUCT red quoting `red()`. Returns `ok`.
        pub fn claim(&mut self, id: &str, ok: bool, red: impl FnOnce() -> String) -> bool {
            if ok {
                println!("[journey] PASS {id}");
                self.0.push((id.to_owned(), Verdict::Pass, String::new()));
            } else {
                let why = red();
                println!("[journey] PRODUCT {id}: {why}");
                self.0.push((id.to_owned(), Verdict::Product, why));
            }
            ok
        }

        /// A check whose earlier step the product failed.
        pub fn cannot(&mut self, id: &str, why: &str) {
            println!("[journey] CANNOT MEASURE (precondition unmet) {id}: {why}");
            self.0
                .push((id.to_owned(), Verdict::CannotMeasure, why.to_owned()));
        }

        /// This proof's own staging failing, without stopping the journey.
        pub fn apparatus(&mut self, id: &str, why: &str) {
            println!("[journey] APPARATUS {id}: {why}");
            self.0
                .push((id.to_owned(), Verdict::Apparatus, why.to_owned()));
        }

        pub fn passed(&self, id: &str) -> bool {
            self.0
                .iter()
                .any(|(i, v, _)| i == id && *v == Verdict::Pass)
        }

        /// The table of every claim, and a red naming each one that did not pass.
        pub fn finish(self) {
            println!("\n[journey] ===== every claim =====");
            for (id, v, _) in &self.0 {
                println!("[journey] {:<16} {id}", format!("{v:?}"));
            }
            let reds: Vec<String> = self
                .0
                .iter()
                .filter(|(_, v, _)| *v != Verdict::Pass)
                .map(|(id, v, why)| {
                    let side = match v {
                        Verdict::Product => "PRODUCT",
                        Verdict::Apparatus => "APPARATUS",
                        _ => "CANNOT MEASURE (precondition unmet)",
                    };
                    format!("{side} {id}: {why}")
                })
                .collect();
            let count = |w: Verdict| self.0.iter().filter(|(_, v, _)| *v == w).count();
            println!(
                "[journey] {} passed, {} PRODUCT, {} APPARATUS, {} CANNOT MEASURE",
                count(Verdict::Pass),
                count(Verdict::Product),
                count(Verdict::Apparatus),
                count(Verdict::CannotMeasure)
            );
            assert!(
                reds.is_empty(),
                "the fresh-user journey is not whole ({} of {} claims):\n{}",
                reds.len(),
                self.0.len(),
                reds.join("\n\n")
            );
        }
    }

    // ------------------------------------------------------------------------------- the world

    /// What one command said, and how long it took.
    pub struct Out {
        pub ok: bool,
        pub said: String,
        pub took: Duration,
    }

    /// The last `n` lines of `said` that hold anything.
    pub fn last_lines(said: &str, n: usize) -> String {
        let lines: Vec<&str> = said.lines().filter(|l| !l.trim().is_empty()).collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    /// Whether `said`'s last three lines name the next action: a `vox` command to run (in
    /// backticks, on a line of its own, or after a colon), or a session to start. A line that
    /// only begins with `vox:` or `vox <verb>:`, as every message of vox's does, names nothing.
    pub fn names_next_action(said: &str) -> bool {
        // A command offered to undo what was done is not the next step.
        let tail: String = last_lines(said, 3)
            .lines()
            .filter(|l| !l.to_ascii_lowercase().contains("undo"))
            .collect::<Vec<_>>()
            .join("\n");
        tail.to_ascii_lowercase().contains("start a new") || told_command(&tail).is_some()
    }

    /// The `vox` command `said` tells the person to run: in backticks, on a line of its own, or
    /// after a colon at the end of a line. Never one with a `<placeholder>`.
    pub fn told_command(said: &str) -> Option<String> {
        let ticked = said
            .split('`')
            .skip(1)
            .step_by(2)
            .find(|s| s.starts_with("vox ") && !s.contains('<'))
            .map(str::to_owned);
        let own_line = || {
            commands_in(said).into_iter().find(|c| {
                !c.contains('<')
                    && !c
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|w| w.ends_with(':'))
            })
        };
        let after_colon = || {
            said.lines().find_map(|l| {
                l.rfind(": vox ")
                    .map(|i| l[i + 2..].trim().to_owned())
                    .filter(|c| !c.contains('<'))
            })
        };
        ticked.or_else(own_line).or_else(after_colon)
    }

    /// The run's root and the person's environment in it.
    pub struct World {
        pub root: PathBuf,
        pub home: PathBuf,
        pub data: PathBuf,
        pub cfg: PathBuf,
        pub t: PathBuf,
        pub repo: PathBuf,
        pub hbin: PathBuf,
        pub apps: PathBuf,
        pub path: String,
        /// Each node's passphrase, as the person typed it.
        pub passes: Mutex<BTreeMap<String, String>>,
        /// The update's loopback release, once there is one.
        pub release_base: Mutex<Option<String>>,
    }

    impl World {
        pub fn new(root: &Path) -> Self {
            let home = root.join("h");
            let w = Self {
                root: root.to_path_buf(),
                data: home.join("vd"),
                cfg: home.join("vc"),
                t: root.join("t"),
                repo: home.join("src/app"),
                hbin: root.join("hb"),
                apps: home.join("Apps"),
                path: format!(
                    "{}:{}:{SYSTEM_PATH}",
                    home.join(".local/bin").display(),
                    root.join("hb").display()
                ),
                home,
                passes: Mutex::new(BTreeMap::new()),
                release_base: Mutex::new(None),
            };
            for d in [&w.home, &w.t, &w.repo, &w.hbin, &w.apps] {
                std::fs::create_dir_all(d)
                    .unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
            }
            w
        }

        /// The installed `vox`, as the person's shell finds it.
        pub fn vox(&self) -> PathBuf {
            self.home.join(".local/bin/vox")
        }

        /// The person's environment: nothing of this process's.
        pub fn env(&self) -> Vec<(String, String)> {
            let mut e: Vec<(String, String)> = [
                ("HOME", self.home.display().to_string()),
                ("PATH", self.path.clone()),
                ("TMPDIR", self.t.display().to_string()),
                ("USER", "journey".to_owned()),
                ("SHELL", "/bin/zsh".to_owned()),
                ("LANG", "en_US.UTF-8".to_owned()),
                ("TERM", "xterm-256color".to_owned()),
                ("VOX_DATA_DIR", self.data.display().to_string()),
                ("VOX_CONFIG_DIR", self.cfg.display().to_string()),
                ("VOX_APPLICATIONS_DIR", self.apps.display().to_string()),
                // A proof's daemon never takes port 1080, and listens on loopback alone.
                ("VOX_PROXY", "127.0.0.1:0".to_owned()),
                ("VOX_LISTEN", "127.0.0.1:0".to_owned()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
            if let Some(b) = self.release_base.lock().unwrap().clone() {
                e.push(("VOX_TEST_RELEASE_BASE".into(), b));
            }
            e
        }

        /// The installed `vox`, run with no terminal: what it said.
        pub fn run(&self, args: &[&str]) -> Out {
            let t0 = Instant::now();
            let out = Command::new(self.vox())
                .args(args)
                .env_clear()
                .envs(self.env())
                .current_dir(&self.repo)
                .stdin(Stdio::null())
                .output()
                .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox {args:?}: {e}"));
            Out {
                ok: out.status.success(),
                said: format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
                took: t0.elapsed(),
            }
        }

        /// `program args` at a terminal of its own, answered as a person: each time it stops at a
        /// question (a line it printed without ending it, and has said nothing more for a moment),
        /// `answer` gets that line and everything said so far, and what it returns is typed with
        /// Enter (`None`: Enter alone). Bounded by `within`.
        pub fn at_terminal(
            &self,
            program: &Path,
            args: &[&str],
            within: Duration,
            answer: &mut dyn FnMut(&str, &str) -> Option<String>,
        ) -> Out {
            use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem as _};
            let t0 = Instant::now();
            let pair = NativePtySystem::default()
                .openpty(PtySize {
                    rows: 50,
                    cols: 200,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .unwrap_or_else(|e| panic!("APPARATUS: cannot open a pty: {e}"));
            let mut cmd = CommandBuilder::new(program);
            cmd.args(args);
            cmd.env_clear();
            for (k, v) in self.env() {
                cmd.env(k, v);
            }
            cmd.cwd(&self.repo);
            let mut child = pair
                .slave
                .spawn_command(cmd)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot start {program:?} at a pty: {e}"));
            drop(pair.slave);
            let mut reader = pair
                .master
                .try_clone_reader()
                .unwrap_or_else(|e| panic!("APPARATUS: pty reader: {e}"));
            let mut input = pair
                .master
                .take_writer()
                .unwrap_or_else(|e| panic!("APPARATUS: pty writer: {e}"));
            let said = Arc::new(Mutex::new(String::new()));
            let grew = Arc::new(Mutex::new(Instant::now()));
            let (sink, stamp) = (Arc::clone(&said), Arc::clone(&grew));
            let master = pair.master;
            let reading = std::thread::spawn(move || {
                let _master = master;
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            sink.lock()
                                .unwrap()
                                .push_str(&String::from_utf8_lossy(&buf[..n]));
                            *stamp.lock().unwrap() = Instant::now();
                        }
                    }
                }
            });
            let text = || said.lock().unwrap().replace('\r', "");
            let mut answered_at = 0usize;
            let status = loop {
                if let Ok(Some(s)) = child.try_wait() {
                    break Some(s);
                }
                if t0.elapsed() > within {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                let now = text();
                let quiet = grew.lock().unwrap().elapsed() > Duration::from_millis(700);
                let open_line = now.rsplit('\n').next().unwrap_or("").to_owned();
                if quiet && now.len() > answered_at && !open_line.trim().is_empty() {
                    let reply = answer(open_line.trim(), &now);
                    println!(
                        "[journey]   at {:?}: {:?} -> {}",
                        program.file_name().unwrap_or_default(),
                        open_line.trim(),
                        match &reply {
                            Some(r) if open_line.to_ascii_lowercase().contains("passphrase") =>
                                if r.is_empty() {
                                    "(nothing)".to_owned()
                                } else {
                                    "(a passphrase)".to_owned()
                                },
                            Some(r) => format!("{r:?}"),
                            None => "(Enter)".to_owned(),
                        }
                    );
                    std::thread::sleep(Duration::from_millis(200));
                    let line = format!("{}\r", reply.unwrap_or_default());
                    let _ = input
                        .write_all(line.as_bytes())
                        .and_then(|()| input.flush());
                    answered_at = text().len() + 1;
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            drop(input);
            std::thread::sleep(Duration::from_millis(300));
            drop(reading);
            let said = text();
            Out {
                ok: status.as_ref().is_some_and(|s| s.success()),
                said: if status.is_none() {
                    format!("{said}\n[journey: stopped after {within:?}, still running]")
                } else {
                    said
                },
                took: t0.elapsed(),
            }
        }

        /// The installed `vox` at a terminal, the person answering: a node's passphrase as they
        /// typed it when they made it (the node named in the question, else `node`), the room's
        /// passphrase for a room's question, and yes to a yes/no question about what they ran.
        pub fn person(&self, args: &[&str], node: &str) -> Out {
            let passes = self.passes.lock().unwrap().clone();
            let mut last = String::new();
            let mut answer = |q: &str, _all: &str| -> Option<String> {
                let lq = q.to_ascii_lowercase();
                if lq.starts_with("again") {
                    return Some(last.clone());
                }
                if lq.contains("passphrase") {
                    let p = if lq.contains("room") {
                        ROOM_PASS.to_owned()
                    } else {
                        passes
                            .iter()
                            .find(|(n, _)| q.contains(n.as_str()))
                            .or_else(|| passes.get_key_value(node))
                            .map(|(_, p)| p.clone())
                            .unwrap_or_default()
                    };
                    last = p.clone();
                    return Some(p);
                }
                if lq.contains("[y/n]") {
                    return Some("y".into());
                }
                None
            };
            println!("[journey] the person runs: vox {}", args.join(" "));
            let out = self.at_terminal(&self.vox(), args, Duration::from_secs(180), &mut answer);
            println!(
                "[journey]   it said, in {:.1} s:\n{}",
                out.took.as_secs_f64(),
                indent(&out.said)
            );
            out
        }

        /// `vox args` as the person runs it; if it fails naming a `vox` command to run first, the
        /// person runs that one, as told, and then `args` again. The first try, and the last.
        pub fn follow(&self, args: &[&str], node: &str) -> (Out, Out) {
            let first = self.person(args, node);
            if first.ok {
                let again = Out {
                    ok: true,
                    said: first.said.clone(),
                    took: first.took,
                };
                return (first, again);
            }
            let told = told_command(&first.said);
            let Some(told) = told else {
                let again = Out {
                    ok: false,
                    said: first.said.clone(),
                    took: first.took,
                };
                return (first, again);
            };
            let told: Vec<&str> = told.split_whitespace().skip(1).collect();
            let _ = self.person(&told, node);
            let again = self.person(args, node);
            (first, again)
        }

        /// The node `name`'s fingerprint, as `vox id` prints it.
        pub fn fingerprint(&self, name: &str) -> Option<String> {
            let o = self.run(&["id", "--node", name]);
            o.said
                .split_whitespace()
                .find(|w| w.len() >= 40 && w.chars().all(|c| c.is_ascii_alphanumeric()))
                .map(str::to_owned)
        }

        /// The nodes `vox node list` says are attached, of `names`.
        pub fn attached(&self, names: &[&str]) -> (Vec<String>, String) {
            let o = self.run(&["node", "list"]);
            let attached = names
                .iter()
                .filter(|n| {
                    o.said.lines().any(|l| {
                        l.split_whitespace().next() == Some(**n)
                            && l.contains("attached")
                            && !l.contains("not attached")
                            && !l.contains("detached")
                    })
                })
                .map(|n| (*n).to_owned())
                .collect();
            (attached, o.said)
        }

        /// The daemon's pid, from its lock.
        pub fn daemon_pid(&self) -> Option<u32> {
            std::fs::read_to_string(self.data.join(".daemon/lock"))
                .ok()
                .and_then(|t| t.trim().parse().ok())
                .filter(|p| alive(*p))
        }

        /// Stop the daemon as a log-out does (SIGTERM), and wait for it to be gone.
        pub fn stop_daemon(&self) -> bool {
            let Some(pid) = self.daemon_pid() else {
                return true;
            };
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let t0 = Instant::now();
            while alive(pid) && t0.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(100));
            }
            !alive(pid)
        }
    }

    pub fn alive(pid: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    pub fn indent(s: &str) -> String {
        s.lines().map(|l| format!("    | {l}\n")).collect()
    }

    // ------------------------------------------------------------------- the release, served

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn record_json(f: &BTreeMap<&str, String>) -> String {
        let body = f
            .iter()
            .map(|(k, v)| {
                if matches!(*k, "schema_version" | "size") {
                    format!("\"{k}\":{v}")
                } else {
                    format!("\"{k}\":\"{v}\"")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("{{{body}}}\n")
    }

    fn write_asset(root: &Path, name: &str, bytes: &[u8]) {
        let dir = root.join("releases/download").join(format!("v{VERSION}"));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        std::fs::write(dir.join(name), bytes).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    }

    fn write_record(root: &Path, name: &str, f: &BTreeMap<&str, String>) {
        let dir = root.join("releases/latest/download");
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        std::fs::write(dir.join(name), record_json(f)).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    }

    /// A release of this build, laid out as GitHub serves one: on macOS Vox.app carrying it (ad-hoc
    /// signed, as `install_sh_proof` makes it), and the standalone `vox`, each with its record.
    pub fn release_tree(root: &Path) {
        let triple = "aarch64-apple-darwin";
        let work = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        let contents = work.path().join("Vox.app/Contents");
        for d in ["MacOS", "Helpers"] {
            std::fs::create_dir_all(contents.join(d)).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        }
        std::fs::copy(VOX, contents.join("MacOS/Vox")).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        std::fs::copy(VOX, contents.join("Helpers/vox"))
            .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        std::fs::write(
            contents.join("Info.plist"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \
                 \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>us.vox.app</string>\
                 <key>CFBundleExecutable</key><string>Vox</string><key>CFBundlePackageType</key>\
                 <string>APPL</string><key>CFBundleShortVersionString</key><string>{VERSION}</string>\
                 <key>LSMinimumSystemVersion</key><string>13.0</string></dict></plist>\n"
            ),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        let app = work.path().join("Vox.app");
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&app)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: codesign: {e}"));
        assert!(
            signed.status.success(),
            "APPARATUS: ad-hoc signing the fixture app"
        );
        let zip_name = format!("Vox-{VERSION}-{triple}.zip");
        let zip = work.path().join(&zip_name);
        let zipped = Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(&app)
            .arg(&zip)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: ditto: {e}"));
        assert!(
            zipped.status.success(),
            "APPARATUS: zipping the fixture app"
        );
        let bytes = std::fs::read(&zip).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        write_asset(root, &zip_name, &bytes);
        let mut f: BTreeMap<&str, String> = BTreeMap::new();
        f.insert("kind", "vox.app-release".into());
        f.insert("schema_version", "1".into());
        f.insert("package", "Vox.app".into());
        f.insert("channel", "stable".into());
        f.insert("target", triple.into());
        f.insert("version", VERSION.into());
        f.insert("size", bytes.len().to_string());
        f.insert("sha256", sha256_hex(&bytes));
        write_record(root, &format!("app-stable-{triple}.json"), &f);

        let bin = std::fs::read(VOX).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        write_asset(root, &format!("vox-{triple}"), &bin);
        f.insert("kind", "vox.standalone-release".into());
        f.insert("package", "vox".into());
        f.insert("size", bin.len().to_string());
        f.insert("sha256", sha256_hex(&bin));
        write_record(root, &format!("stable-{triple}.json"), &f);
    }

    // ------------------------------------------------------------- the harnesses and the model

    /// Every string in `v`, joined by newlines.
    pub fn strings_of(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::String(s) => {
                out.push_str(s);
                out.push('\n');
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| strings_of(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| strings_of(x, out)),
            _ => {}
        }
    }

    /// Children this proof started, stopped however it ends; and the daemon, by its own pid.
    pub struct Stop {
        pub children: Vec<Child>,
        pub data: PathBuf,
        pub codex: Option<(PathBuf, PathBuf)>,
        pub tmux: Option<(PathBuf, PathBuf)>,
    }

    impl Drop for Stop {
        fn drop(&mut self) {
            if let Some((tmux, socket)) = &self.tmux {
                let _ = Command::new(tmux)
                    .arg("-S")
                    .arg(socket)
                    .arg("kill-server")
                    .output();
            }
            if let Some((codex, home)) = &self.codex {
                let _ = Command::new(codex)
                    .args(["app-server", "daemon", "stop"])
                    .env_clear()
                    .env("PATH", SYSTEM_PATH)
                    .env("HOME", home.parent().unwrap_or(home))
                    .env("CODEX_HOME", home)
                    .output();
            }
            if let Some(pid) = std::fs::read_to_string(self.data.join(".daemon/lock"))
                .ok()
                .and_then(|t| t.trim().parse::<u32>().ok())
            {
                let _ = Command::new("/bin/kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
                let t0 = Instant::now();
                while alive(pid) && t0.elapsed() < Duration::from_secs(15) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            for c in &mut self.children {
                let _ = c.kill();
                let _ = c.wait();
            }
            // A node kept through the Keychain is kept under its directory, which is this run's:
            // nothing of the run's stays in the login keychain.
            if let Ok(nodes) = std::fs::read_dir(self.data.join("nodes")) {
                for n in nodes.flatten() {
                    let _ = Command::new("/usr/bin/security")
                        .args(["delete-generic-password", "-s", "us.vox.node", "-a"])
                        .arg(n.path())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }

    /// One harness, as installed here, and how a turn of it is run in the repo.
    pub struct Harness {
        pub key: &'static str,
        pub name: &'static str,
        pub node: &'static str,
        pub program: PathBuf,
        pub args: Vec<String>,
        pub env: Vec<(String, String)>,
    }

    /// Where `key` reads the skill pack under `home`.
    pub fn pack_in(home: &Path, key: &str) -> PathBuf {
        let dir = match key {
            "claude" => home.join(".claude"),
            "codex" => home.join(".codex"),
            _ => home.join(".config/opencode"),
        };
        dir.join("skills/vox-agent-comms")
    }

    /// The command lines a session's status names: each `vox …` line, indented, as status prints
    /// its one command.
    pub fn commands_in(said: &str) -> Vec<String> {
        said.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("vox ") && !l.starts_with("vox:"))
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The number of sentences in `text`, a hook's guidance: a command on a line of its own, or
    /// in backticks, is not prose.
    pub fn sentences(text: &str) -> usize {
        let prose: String = text
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("vox ") && !t.starts_with('$')
            })
            .collect::<Vec<_>>()
            .join(" ");
        let prose: String = prose
            .split('`')
            .enumerate()
            .map(|(i, s)| if i % 2 == 1 { "CMD" } else { s })
            .collect();
        // Each run of words up to a full stop, or to the end, is one sentence.
        let mut count = 0;
        let mut words = false;
        let chars: Vec<char> = prose.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if matches!(c, '.' | '!' | '?') && chars.get(i + 1).is_none_or(|n| n.is_whitespace()) {
                if words {
                    count += 1;
                }
                words = false;
            } else if c.is_alphanumeric() {
                words = true;
            }
        }
        count + usize::from(words)
    }

    pub fn run() {
        watchdog::arm_for(Duration::from_secs(2700));
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            panic!(
                "CANNOT MEASURE: the journey installs Vox.app and confines each harness with macOS \
                 sandbox-exec, so it runs on an Apple silicon Mac only"
            );
        }
        test_knobs::require(&["VOX_TEST_RELEASE_BASE"]);
        let mut l = Ledger::default();

        // ---- the harnesses, as installed here ----
        let which = |bin: &str| -> Option<PathBuf> {
            std::env::var_os("PATH").and_then(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join(bin))
                    .find(|p| p.is_file())
            })
        };
        let mut programs: BTreeMap<&str, PathBuf> = BTreeMap::new();
        for (key, _, _) in HARNESSES {
            let p = which(key).unwrap_or_else(|| {
                panic!("CANNOT MEASURE: {key} is not on PATH, so it cannot be started")
            });
            programs.insert(key, oc_sandbox::real(&p));
        }
        let tmux = which("tmux")
            .unwrap_or_else(|| panic!("CANNOT MEASURE: tmux is not on PATH"))
            .canonicalize()
            .unwrap_or_else(|e| panic!("APPARATUS: tmux: {e}"));
        let install_of = |bin: &Path| -> PathBuf {
            let dir = bin
                .parent()
                .expect("APPARATUS: a harness binary has a directory");
            if dir.file_name().is_some_and(|n| n == "bin") && bin.ends_with("codex") {
                dir.parent().unwrap_or(dir).to_path_buf()
            } else {
                dir.to_path_buf()
            }
        };

        // ---- the root: short, for the daemon's control socket ----
        let tmp = tempfile::Builder::new()
            .prefix("vj")
            .tempdir_in("/private/tmp")
            .unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
        // `VOX_JOURNEY_KEEP=1` keeps the run's root, to read after a red.
        let tmp = if std::env::var_os("VOX_JOURNEY_KEEP").is_some() {
            let kept = tmp.keep();
            println!("[journey] the run's root is kept: {}", kept.display());
            tempfile::Builder::new()
                .prefix("vj-unused")
                .tempdir_in("/private/tmp")
                .map(|t| (t, kept))
                .unwrap_or_else(|e| panic!("APPARATUS: {e}"))
        } else {
            let p = tmp.path().to_path_buf();
            (tmp, p)
        };
        let w = World::new(&oc_sandbox::real(&tmp.1));
        // The harnesses on the person's PATH, by name, as their installers put them.
        for (key, p) in &programs {
            std::os::unix::fs::symlink(p, w.hbin.join(key))
                .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        }
        // tmux too, as a person who runs a harness in it has it.
        std::os::unix::fs::symlink(&tmux, w.hbin.join("tmux"))
            .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        let mut stop = Stop {
            children: vec![],
            data: w.data.clone(),
            codex: Some((programs["codex"].clone(), w.home.join(".codex"))),
            tmux: None,
        };

        // ================================================================ 1. install
        let rel = w.root.join("rel");
        release_tree(&rel);
        let server = release_server::serve(&rel)
            .unwrap_or_else(|e| panic!("APPARATUS: the loopback release did not start: {e}"));
        let installed = Command::new("/bin/sh")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
            .env_clear()
            .envs(w.env())
            .env("VOX_RELEASE_BASE", &server.base)
            .current_dir(&w.home)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run install.sh: {e}"));
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&installed.stdout),
            String::from_utf8_lossy(&installed.stderr)
        );
        println!("[journey] 1. install.sh said:\n{}", indent(&said));
        // The person's shell finds `vox` where install.sh put it, or finds none.
        let version = if w.vox().exists() {
            w.run(&["--version"]).said
        } else {
            format!("(no {})", w.vox().display())
        };
        let ok = l.claim(
            "J1.install",
            installed.status.success() && version.contains(VERSION),
            || {
                format!(
                    "install.sh exited {:?}; the installed vox said {:?}; install.sh said:\n{}",
                    installed.status.code(),
                    version.trim(),
                    last_lines(&said, 12)
                )
            },
        );
        if !ok {
            l.finish();
            return;
        }
        let missing: Vec<String> = HARNESSES
            .iter()
            .filter(|(k, _, _)| !pack_in(&w.home, k).join("SKILL.md").is_file())
            .map(|(k, _, _)| k.to_string())
            .collect();
        l.claim("J1.pack", missing.is_empty(), || {
            format!(
                "after install, no skill pack where {missing:?} read it; install.sh said:\n{}",
                last_lines(&said, 12)
            )
        });
        l.claim(
            "J8.install",
            names_next_action(&said) && last_lines(&said, 4).contains("vox setup"),
            || {
                format!(
                    "install.sh's last lines must name the next step, `vox setup`; they were:\n{}",
                    last_lines(&said, 4)
                )
            },
        );
        *w.release_base.lock().unwrap() = Some(server.base.clone());

        // ================================================================ the person's harnesses
        let port_file = w.root.join("model.port");
        let log = w.root.join("model.jsonl");
        let run_file = w.root.join("model.run");
        let model = Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/model_standin.py"
            ))
            .arg(&port_file)
            .arg(&log)
            .arg("--run-file")
            .arg(&run_file)
            .env_clear()
            .env("PATH", SYSTEM_PATH)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start the stand-in model: {e}"));
        stop.children.push(model);
        let t0 = Instant::now();
        let port: u16 = loop {
            if let Some(p) = std::fs::read_to_string(&port_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                break p;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(20),
                "APPARATUS: the stand-in model did not listen"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let url = format!("http://127.0.0.1:{port}");
        for d in [w.home.join(".codex"), w.home.join(".config/opencode")] {
            std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        }
        std::fs::write(
            w.home.join(".codex/config.toml"),
            format!(
                "model = \"stub-model\"\nmodel_provider = \"standin\"\n\n[model_providers.standin]\n\
                 name = \"standin\"\nbase_url = \"{url}/v1\"\nwire_api = \"responses\"\n\
                 env_key = \"STANDIN_API_KEY\"\n"
            ),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: Codex's config.toml: {e}"));
        std::fs::write(
            w.home.join(".config/opencode/opencode.json"),
            serde_json::json!({
                "autoupdate": false, "share": "disabled",
                "provider": { "standin": {
                    "npm": "@ai-sdk/openai-compatible", "name": "standin",
                    "options": { "baseURL": format!("{url}/v1"), "apiKey": "made-up-key-for-a-stand-in" },
                    "models": { "stub-model": { "name": "stub-model" } } }},
                "model": "standin/stub-model",
                "permission": { "bash": "allow" }
            })
            .to_string(),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: OpenCode's opencode.json: {e}"));
        std::fs::write(
            w.home.join(".claude.json"),
            serde_json::json!({
                "hasCompletedOnboarding": true, "theme": "dark", "numStartups": 5,
                "projects": { w.repo.display().to_string():
                    { "hasTrustDialogAccepted": true, "hasCompletedProjectOnboarding": true } },
            })
            .to_string(),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: Claude Code's .claude.json: {e}"));

        // ================================================================ 2. vox setup
        let mut refused_empty: Vec<String> = Vec::new();
        let mut asked_names: Vec<String> = Vec::new();
        let mut current: Option<String> = None;
        let mut last_pass = String::new();
        let setup = {
            let mut answer = |q: &str, all: &str| -> Option<String> {
                let lq = q.to_ascii_lowercase();
                for (_, name, mine) in HARNESSES {
                    if q.starts_with(&format!("a node for {name}")) {
                        asked_names.push(name.to_owned());
                        current = Some(mine.to_owned());
                        return Some(mine.to_owned());
                    }
                }
                if lq.starts_with("its name") {
                    current = Some(PERSON.to_owned());
                    return Some(PERSON.to_owned());
                }
                if lq.contains("create a node for you") {
                    return Some("y".into());
                }
                if lq.starts_with("again") {
                    return Some(last_pass.clone());
                }
                if lq.contains("passphrase") {
                    let node = q
                        .split_whitespace()
                        .find(|w| w.contains('-') || *w == PERSON)
                        .map(|w| w.trim_end_matches(':').to_owned())
                        .or_else(|| current.clone())
                        .unwrap_or_default();
                    // Empty first; a person refused types one, and the red is kept.
                    let tail: String = all
                        .chars()
                        .rev()
                        .take(300)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    let refused = tail.contains("must have a passphrase");
                    let p = if refused {
                        if !refused_empty.contains(&node) {
                            refused_empty.push(node.clone());
                        }
                        format!("pp {node} typed")
                    } else {
                        EMPTY.to_owned()
                    };
                    last_pass = p.clone();
                    return Some(p);
                }
                // A question the journey does not know: a person takes its default.
                None
            };
            println!("[journey] 2. the person runs vox setup");
            w.at_terminal(&w.vox(), &["setup"], Duration::from_secs(600), &mut answer)
        };
        println!("[journey] 2. vox setup said:\n{}", indent(&setup.said));
        {
            let mut passes = w.passes.lock().unwrap();
            for n in HARNESSES.iter().map(|h| h.2).chain([PERSON]) {
                let p = if refused_empty.iter().any(|r| r == n) {
                    format!("pp {n} typed")
                } else {
                    EMPTY.to_owned()
                };
                passes.insert(n.to_owned(), p);
            }
        }
        let nodes: Vec<&str> = HARNESSES.iter().map(|h| h.2).chain([PERSON]).collect();
        let list = w.run(&["node", "list"]);
        let on_disk: Vec<&str> = nodes
            .iter()
            .copied()
            .filter(|n| w.data.join("nodes").join(n).is_dir() || list.said.contains(n))
            .collect();
        l.claim(
            "J2.names",
            setup.ok && on_disk.len() == nodes.len() && asked_names.len() == HARNESSES.len(),
            || {
                format!(
                    "setup was asked to name {nodes:?} (it asked a name for {asked_names:?}); nodes \
                     made: {on_disk:?}; exit ok {}; it ended:\n{}",
                    setup.ok,
                    last_lines(&setup.said, 8)
                )
            },
        );
        l.claim("J2.empty_passphrase", refused_empty.is_empty(), || {
            format!(
                "setup refused an empty passphrase for {refused_empty:?} (ruled optional \
                 2026-10-10): \"{}\"",
                setup
                    .said
                    .lines()
                    .find(|l| l.contains("must have a passphrase"))
                    .unwrap_or("")
                    .trim()
            )
        });
        let wired = |when: &str| -> Vec<String> {
            let mut wrong = vec![];
            let claude =
                std::fs::read_to_string(w.home.join(".claude/settings.json")).unwrap_or_default();
            if !(claude.contains("vox agent hook") && claude.contains("claude-mine")) {
                wrong.push(format!(
                    "~/.claude/settings.json {when} runs no `vox agent hook` for claude-mine"
                ));
            }
            let codex =
                std::fs::read_to_string(w.home.join(".codex/hooks.json")).unwrap_or_default();
            if !(codex.contains("vox agent hook") && codex.contains("codex-mine")) {
                wrong.push(format!(
                    "~/.codex/hooks.json {when} runs no `vox agent hook` for codex-mine"
                ));
            }
            let oc = std::fs::read_to_string(w.home.join(".config/opencode/plugin/vox.js"))
                .or_else(|_| {
                    std::fs::read_to_string(w.home.join(".config/opencode/plugins/vox.js"))
                })
                .unwrap_or_default();
            if !oc.contains("opencode-mine") {
                wrong.push(format!("OpenCode's plugin {when} names no opencode-mine"));
            }
            wrong
        };
        let wrong = wired("after setup");
        let by_hand =
            setup.said.contains("\"hooks\"") || setup.said.to_ascii_lowercase().contains("merge");
        l.claim("J2.wired", wrong.is_empty() && !by_hand, || {
            format!(
                "{wrong:?}{}",
                if by_hand {
                    "; setup printed hook JSON to merge by hand"
                } else {
                    ""
                }
            )
        });
        let (attached, said) = w.attached(&nodes);
        l.claim("J2.attached", attached.len() == nodes.len(), || {
            format!(
                "after setup, attached: {attached:?} of {nodes:?}; `vox node list` said:\n{said}"
            )
        });
        l.claim("J8.setup", names_next_action(&setup.said), || {
            format!(
                "setup's last lines name no next action:\n{}",
                last_lines(&setup.said, 3)
            )
        });

        // The person does what setup's closing lines say is next, each as told.
        for line in setup.said.lines().filter(|l| l.contains("next")) {
            if let Some(cmd) = told_command(line) {
                let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
                let _ = w.person(&args, "");
            }
        }

        // ================================================================ 3. the repo, the room
        let git = |args: &[&str]| {
            let ok = Command::new("/usr/bin/git")
                .args(args)
                .env_clear()
                .envs(w.env())
                .env("GIT_AUTHOR_NAME", "journey")
                .env("GIT_AUTHOR_EMAIL", "journey@example.invalid")
                .env("GIT_COMMITTER_NAME", "journey")
                .env("GIT_COMMITTER_EMAIL", "journey@example.invalid")
                .current_dir(&w.repo)
                .output()
                .is_ok_and(|o| o.status.success());
            assert!(ok, "APPARATUS: git {args:?} in the stub repo");
        };
        std::fs::write(w.repo.join("README.md"), "# app\n")
            .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        git(&["init", "-q"]);
        git(&["add", "README.md"]);
        git(&["commit", "-q", "-m", "init"]);

        // As the person: a refusal that names a command to run first is followed, and the red
        // kept.
        let (first, made) = w.follow(
            &["room", "create", "--name", ROOM, "--node", PERSON],
            PERSON,
        );
        // The room's id, as the person's node lists it.
        let rooms = w.run(&["room", "list", "--node", PERSON]);
        let room_id = rooms
            .said
            .lines()
            .find(|l| l.contains(ROOM))
            .and_then(|l| {
                l.split_whitespace().find(|t| {
                    t.len() >= 8 && t.chars().all(|c| c.is_ascii_alphanumeric()) && *t != ROOM
                })
            })
            .unwrap_or(ROOM)
            .to_owned();
        println!(
            "[journey] 3. the room: {room_id} (`vox room list` said: {:?})",
            rooms.said.trim()
        );
        let room = room_id.as_str();
        let link = w.run(&["room", "link", room, "--node", PERSON]);
        let link = link
            .said
            .split_whitespace()
            .find(|t| t.starts_with("vox://"))
            .map(str::to_owned);
        l.claim("J3.room_first_try", first.ok, || {
            format!(
                "the person's first `vox room create` after setup was refused:\n{}",
                first.said
            )
        });
        let room_ok = l.claim("J3.room", made.ok && link.is_some(), || {
            format!("the person's room: `vox room create` said:\n{}", made.said)
        });
        let link = link.unwrap_or_default();

        // ================================================================ 4. each harness
        let canary = oc_sandbox::Canary::plant();
        let installs: Vec<PathBuf> = programs.values().map(|p| install_of(p)).collect();
        let mut readable: Vec<&Path> = installs.iter().map(PathBuf::as_path).collect();
        readable.push(Path::new(VOX));
        // tmux's own install and its libraries, read-only, as `claude_live_proof` confines it.
        let mut tmux_dirs: Vec<PathBuf> = vec![tmux
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| panic!("APPARATUS: tmux's install has no directory"))];
        for lib in ["utf8proc", "ncurses", "libevent"] {
            let p = PathBuf::from(format!("/opt/homebrew/opt/{lib}"));
            if p.exists() {
                tmux_dirs.push(oc_sandbox::real(&p));
            }
        }
        readable.extend(tmux_dirs.iter().map(PathBuf::as_path));
        let profile = w.root.join("harness.sb");
        std::fs::write(
            &profile,
            oc_sandbox::offline_profile(&[&w.root], &readable, port),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: the sandbox profile: {e}"));
        oc_sandbox::probe_profile(&profile, &canary, "harnesses on the stand-in model");

        let xdg = |d: &str| w.root.join("xdg").join(d).display().to_string();
        for d in ["data", "state", "cache"] {
            std::fs::create_dir_all(w.root.join("xdg").join(d))
                .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        }
        let harnesses: Vec<Harness> = HARNESSES
            .iter()
            .map(|(key, name, node)| {
                let (args, env): (Vec<&str>, Vec<(String, String)>) = match *key {
                    "claude" => (
                        vec![
                            "-p",
                            "--model",
                            "claude-sonnet-4-5",
                            "--allowedTools=Bash(vox:*)",
                            "hello",
                        ],
                        vec![
                            ("ANTHROPIC_BASE_URL".into(), url.clone()),
                            (
                                "ANTHROPIC_API_KEY".into(),
                                "made-up-key-for-a-stand-in".into(),
                            ),
                            ("CLAUDE_CODE_TMPDIR".into(), w.t.display().to_string()),
                            (
                                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(),
                                "1".into(),
                            ),
                            ("DISABLE_AUTOUPDATER".into(), "1".into()),
                        ],
                    ),
                    "codex" => (
                        vec![
                            "exec",
                            "--skip-git-repo-check",
                            "--dangerously-bypass-approvals-and-sandbox",
                            "hello",
                        ],
                        vec![
                            (
                                "CODEX_HOME".into(),
                                w.home.join(".codex").display().to_string(),
                            ),
                            (
                                "STANDIN_API_KEY".into(),
                                "made-up-key-for-a-stand-in".into(),
                            ),
                        ],
                    ),
                    _ => (
                        vec!["run", "--model", "standin/stub-model", "hello"],
                        vec![
                            (
                                "XDG_CONFIG_HOME".into(),
                                w.home.join(".config").display().to_string(),
                            ),
                            ("XDG_DATA_HOME".into(), xdg("data")),
                            ("XDG_STATE_HOME".into(), xdg("state")),
                            ("XDG_CACHE_HOME".into(), xdg("cache")),
                            ("OPENCODE_DISABLE_MODELS_FETCH".into(), "1".into()),
                            ("OPENCODE_DISABLE_AUTOUPDATE".into(), "1".into()),
                            ("OPENCODE_DISABLE_LSP_DOWNLOAD".into(), "1".into()),
                            ("OPENCODE_DISABLE_CLAUDE_CODE".into(), "1".into()),
                        ],
                    ),
                };
                Harness {
                    key,
                    name,
                    node,
                    program: programs[key].clone(),
                    args: args.into_iter().map(str::to_owned).collect(),
                    env,
                }
            })
            .collect();

        // One session of `h` in the repo, confined, against the stand-in: what it printed, or why
        // it did not finish a turn (APPARATUS).
        let sent_len = || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .count()
        };
        let once = |h: &Harness, told: &str| -> Result<(String, String), String> {
            std::fs::write(&run_file, told).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
            let before = sent_len();
            let t0 = Instant::now();
            let out = Command::new("/usr/bin/sandbox-exec")
                .env_clear()
                .envs(w.env())
                .envs(h.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .arg("-f")
                .arg(&profile)
                .arg(&h.program)
                .args(&h.args)
                .current_dir(&w.repo)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("cannot start {}: {e}", h.name))?;
            let said = format!(
                "{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let all = std::fs::read_to_string(&log).unwrap_or_default();
            let mut sent = String::new();
            for line in all.lines().skip(before) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    strings_of(&v["body"], &mut sent);
                }
            }
            canary.check(&said, &format!("{}'s output", h.name));
            canary.check(&sent, &format!("what {} sent its model", h.name));
            println!(
                "[journey]   {} session: exit {:?} after {:.1}s; it printed:\n{}",
                h.name,
                out.status.code(),
                t0.elapsed().as_secs_f64(),
                indent(&String::from_utf8_lossy(&out.stdout))
            );
            if !out.status.success() || all.lines().count() == before {
                return Err(format!(
                    "{} did not finish a turn against the stand-in model (exit {:?}): {}",
                    h.name,
                    out.status.code(),
                    last_lines(&said, 15)
                ));
            }
            Ok((sent, said))
        };
        // OpenCode's shell tool has come back empty for a command that prints (measured: `vox
        // agent status` run in the same sandbox printed its three lines): smoke, so the session
        // is run once more, and a second empty answer is the apparatus's.
        let session = |h: &Harness, told: &str| -> Result<(String, String), String> {
            let empty = |said: &str| said.contains("SAID:\n(no output)");
            match once(h, told)? {
                (_, said) if empty(&said) => {
                    println!(
                        "[journey]   {}'s shell tool returned nothing; once more",
                        h.name
                    );
                    match once(h, told)? {
                        (_, said) if empty(&said) => Err(format!(
                            "{}'s shell tool returned no output, twice, for a command that prints",
                            h.name
                        )),
                        ok => Ok(ok),
                    }
                }
                ok => Ok(ok),
            }
        };
        const ASK: &str = "isn't tied to a Vox room";

        // A person's OpenCode has run before: its first start fetches its plugin folder's
        // dependencies, which the offline sandbox refuses, and its shell tool has then come back
        // empty. One session that runs nothing, before the journey's own.
        if let Some(oc) = harnesses.iter().find(|h| h.key == "opencode") {
            let _ = once(oc, "-");
        }
        let mut ready: BTreeMap<&str, bool> = BTreeMap::new();
        // Each harness's session that reached the room ask, before any answer: what it printed.
        let mut asks: Vec<(&str, &str, String)> = Vec::new();
        for h in &harnesses {
            let id = |c: &str| format!("J4.{}.{c}", h.key);
            let mut followed: Vec<String> = Vec::new();
            let mut reached = None;
            for round in 0..4 {
                let (sent, said) = match session(h, "") {
                    Ok(s) => s,
                    Err(why) => {
                        l.apparatus(&id("session"), &why);
                        break;
                    }
                };
                if said.contains(ASK) || sent.contains(ASK) {
                    reached = Some((sent, said));
                    break;
                }
                let cmds = commands_in(&said);
                let one = l.claim(
                    &id(&format!("one_command.{round}")),
                    said.contains("VOX STATUS SAID:") && cmds.len() == 1,
                    || {
                        format!(
                            "a session must say what is missing and the one command; it named \
                             {cmds:?} and printed:\n{}",
                            last_lines(&said, 12)
                        )
                    },
                );
                if !one {
                    break;
                }
                let cmd = cmds[0].clone();
                if followed.contains(&cmd) {
                    l.claim(&id("reaches_room"), false, || {
                        format!("the session named `{cmd}` again after the person ran it")
                    });
                    break;
                }
                let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
                let out = w.person(&args, h.node);
                l.claim(
                    &format!(
                        "J8.{}.{}",
                        h.key,
                        args.iter().take(2).copied().collect::<Vec<_>>().join("-")
                    ),
                    names_next_action(&out.said),
                    || {
                        format!(
                            "`{cmd}`'s last lines name no next action:\n{}",
                            last_lines(&out.said, 3)
                        )
                    },
                );
                followed.push(cmd);
            }
            let Some((sent, said)) = reached else {
                if !l.0.iter().any(|(i, _, _)| i == &id("reaches_room")) {
                    l.claim(&id("reaches_room"), false, || {
                        format!("after the person ran {followed:?}, the session never reached the room ask")
                    });
                }
                l.cannot(
                    &id("person_asked"),
                    "the session never reached the room ask",
                );
                continue;
            };
            l.claim(&id("reaches_room"), true, String::new);
            // **Vox asks the person** for the repo's room, not only the model. The control: a
            // session whose model runs nothing and answers "ok", so anything of the ask the
            // harness shows its person came from Vox (a hook's message to the person, say), not
            // from a model relaying it or a tool's output echoed. What the model was given (`sent`)
            // is not shown to the person.
            let _ = sent;
            match session(h, "-") {
                Ok((_, quiet)) => {
                    let shown = quiet.contains(ASK);
                    l.claim(&id("person_asked"), shown, || {
                        format!(
                            "with a model that relays nothing, {} showed the person no room ask: \
                             the ask reached only the model (the hook's context, and the status \
                             a model runs); it printed:\n{}",
                            h.name,
                            last_lines(&quiet, 8)
                        )
                    });
                }
                Err(why) => l.apparatus(&id("person_asked"), &why),
            }
            asks.push((h.key, h.node, said));
        }

        // ---- the person answers the first ask: one answer is the repo's room, for every
        // harness started in it ----
        let bound_by = match (room_ok, asks.first()) {
            (true, Some((key, node, said))) => {
                let join = commands_in(said)
                    .into_iter()
                    .find(|c| c.starts_with("vox room join"))
                    .unwrap_or_else(|| {
                        format!(
                            "vox room join <link> --node {node} --bind {}",
                            w.repo.display()
                        )
                    });
                let join = join.replace("<link>", &link);
                let args: Vec<&str> = join.split_whitespace().skip(1).collect();
                let (_, out) = w.follow(&args, node);
                l.claim(
                    &format!("J8.{key}.room-join"),
                    names_next_action(&out.said),
                    || {
                        format!(
                            "`{join}`'s last lines name no next action:\n{}",
                            last_lines(&out.said, 3)
                        )
                    },
                );
                Some(format!(
                    "`{join}`, which said: {}",
                    last_lines(&out.said, 3)
                ))
            }
            _ => None,
        };
        for h in &harnesses {
            let id = |c: &str| format!("J4.{}.{c}", h.key);
            let Some(how) = &bound_by else {
                l.cannot(
                    &id("bound"),
                    "the person has no room, or no session asked for one",
                );
                continue;
            };
            match session(h, "") {
                Ok((_, said)) => {
                    // The session says it works in the room, and its node holds the room.
                    let holds = w.run(&["room", "list", "--node", h.node]);
                    let ok = said.contains("works in room")
                        && !said.contains(ASK)
                        && holds.said.contains(room);
                    ready.insert(h.key, ok);
                    l.claim(&id("bound"), ok, || {
                        format!(
                            "after the person bound the repo ({how}), {}'s next session must work \
                             in the room, its node holding it; it printed:\n{}\n`vox room list \
                             --node {}` said: {}",
                            h.name,
                            last_lines(&said, 10),
                            h.node,
                            holds.said.trim()
                        )
                    });
                }
                Err(why) => l.apparatus(&id("bound"), &why),
            }
        }

        // ================================================================ 5. trust and drive
        let person_fp = w.fingerprint(PERSON);
        let (_, offers) = w.follow(&["trust", "offers", "--node", PERSON], PERSON);
        for h in &harnesses {
            let Some(fp) = w.fingerprint(h.node) else {
                l.cannot(
                    &format!("J5.trust.{}", h.key),
                    "the agent's node has no fingerprint",
                );
                continue;
            };
            l.claim(
                &format!("J5.offered.{}", h.key),
                offers.said.contains(&fp[..12]),
                || {
                    format!(
                        "the person's node was not offered {} ({}); `vox trust offers` said:\n{}",
                        h.node,
                        &fp[..12],
                        offers.said
                    )
                },
            );
            let Some(pfp) = person_fp.clone() else {
                l.cannot(
                    &format!("J5.trust.{}", h.key),
                    "the person's node has no fingerprint",
                );
                continue;
            };
            let (_, a) = w.follow(
                &["trust", "add", &fp, "--name", h.key, "--node", PERSON],
                PERSON,
            );
            let (_, b) = w.follow(
                &[
                    "trust", "add", &pfp, "--name", PERSON, "--drive", "--node", h.node,
                ],
                h.node,
            );
            let mine = w.run(&["trust", "list", "--node", PERSON]);
            let theirs = w.run(&["trust", "list", "--node", h.node]);
            let drive_line = theirs
                .said
                .lines()
                .any(|l| l.contains(PERSON) && l.contains("drive"));
            l.claim(
                &format!("J5.trust.{}", h.key),
                a.ok && b.ok && mine.said.contains(h.key) && drive_line,
                || {
                    format!(
                        "the person and {} must trust each other, with drive for the person: \
                         robin's keyring:\n{}\n{}'s keyring:\n{}",
                        h.node, mine.said, h.node, theirs.said
                    )
                },
            );
            l.claim(
                &format!("J8.{}.trust-add", h.key),
                names_next_action(&b.said),
                || {
                    format!(
                        "`vox trust add … --drive`'s last lines name no next action:\n{}",
                        last_lines(&b.said, 3)
                    )
                },
            );
        }

        // ================================================================ 6. the agent posts
        let read_until = |token: &str, within: Duration| -> (bool, String) {
            let t0 = Instant::now();
            loop {
                let r = w.run(&["room", "read", room, "--node", PERSON]);
                if r.said.contains(token) {
                    return (true, r.said);
                }
                if t0.elapsed() > within {
                    return (false, r.said);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        };
        for h in &harnesses {
            let id = |c: &str| format!("J6.{}.{c}", h.key);
            if !ready.get(h.key).copied().unwrap_or(false) {
                l.cannot(
                    &id("read"),
                    "the harness's session never worked in the room",
                );
                l.cannot(
                    &id("listed"),
                    "the harness's session never worked in the room",
                );
                continue;
            }
            let token = format!("posted-by-{}-{}", h.key, std::process::id());
            let told = format!("vox room post {room} --node {} {token}", h.node);
            match session(h, &told) {
                Ok((_, said)) => {
                    let (seen, room) = read_until(&token, Duration::from_secs(30));
                    l.claim(&id("read"), said.contains("VOX RUN SAID:") && seen, || {
                        format!(
                            "{} ran `{told}`, and the person did not read it within 30 s; the \
                             session printed:\n{}\nthe person's `vox room read`:\n{}",
                            h.name,
                            last_lines(&said, 6),
                            last_lines(&room, 8)
                        )
                    });
                }
                Err(why) => l.apparatus(&id("read"), &why),
            }
            let s = w.run(&["room", "sessions", room, "--node", PERSON, "--json"]);
            let listed = s
                .said
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .any(|v| v["harness"] == h.key);
            let plain = w.run(&["room", "sessions", room, "--node", PERSON]);
            l.claim(&id("listed"), listed, || {
                format!(
                    "the person found no {} Session in the room; `vox room sessions` said:\n{}\n\
                     and with --json:\n{}",
                    h.name, plain.said, s.said
                )
            });
        }
        std::fs::write(&run_file, "").unwrap_or_else(|e| panic!("APPARATUS: {e}"));

        // ---- an interactive Claude Code, found, driven and renamed from Vox ----
        if ready.get("claude").copied().unwrap_or(false) && l.passed("J5.trust.claude") {
            let claude = &harnesses[0];
            // Its model answers "ok" and runs nothing, so no approval is pending when the person
            // drives: what is measured is driving an idle session.
            std::fs::write(&run_file, "-").unwrap_or_else(|e| panic!("APPARATUS: {e}"));
            let socket = w.root.join("t.sock");
            stop.tmux = Some((tmux.clone(), socket.clone()));
            let mut env = w.env();
            env.extend([
                ("ANTHROPIC_BASE_URL".to_owned(), url.clone()),
                (
                    "ANTHROPIC_AUTH_TOKEN".to_owned(),
                    "made-up-token-for-a-stand-in".to_owned(),
                ),
                ("CLAUDE_CODE_TMPDIR".to_owned(), w.t.display().to_string()),
                (
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_owned(),
                    "1".to_owned(),
                ),
                ("DISABLE_AUTOUPDATER".to_owned(), "1".to_owned()),
            ]);
            let tm = |args: &[&str]| -> String {
                let o = Command::new(&tmux)
                    .env_clear()
                    .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .arg("-S")
                    .arg(&socket)
                    .args(["-f", "/dev/null"])
                    .args(args)
                    .output();
                o.map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                    .unwrap_or_default()
            };
            let started = Command::new("/usr/bin/sandbox-exec")
                .env_clear()
                .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .arg("-f")
                .arg(&profile)
                .arg(&tmux)
                .arg("-S")
                .arg(&socket)
                .args([
                    "-f",
                    "/dev/null",
                    "new-session",
                    "-d",
                    "-x",
                    "160",
                    "-y",
                    "50",
                    "-c",
                ])
                .arg(&w.repo)
                .arg("/bin/sh")
                .output()
                .is_ok_and(|o| o.status.success());
            if started {
                let _ = tm(&[
                    "send-keys",
                    "-t",
                    ":0.0",
                    "-l",
                    &format!("{} --model claude-sonnet-4-5", claude.program.display()),
                ]);
                let _ = tm(&["send-keys", "-t", ":0.0", "Enter"]);
            }
            let screen = || tm(&["capture-pane", "-p", "-t", ":0.0"]);
            let guard_ok = |s: &str| {
                ![
                    "Select login method",
                    "API key",
                    "Paste code",
                    "Log in to",
                    "trust this folder",
                ]
                .iter()
                .any(|b| s.contains(b))
            };
            let t0 = Instant::now();
            let mut up = false;
            while started && t0.elapsed() < Duration::from_secs(90) {
                let s = screen();
                if !guard_ok(&s) {
                    break;
                }
                if s.contains("Claude Code v")
                    && s.lines().filter(|l| l.matches('─').count() >= 20).count() >= 2
                {
                    up = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            if !up {
                for c in ["found", "said", "renamed", "while_waiting"] {
                    l.apparatus(
                        &format!("J6.drive.{c}"),
                        &format!(
                            "an interactive Claude Code did not come up in tmux; the pane:\n{}",
                            screen()
                        ),
                    );
                }
            } else {
                let _ = tm(&["send-keys", "-t", ":0.0", "-l", "hello from the terminal"]);
                std::thread::sleep(Duration::from_millis(600));
                let _ = tm(&["send-keys", "-t", ":0.0", "Enter"]);
                let t0 = Instant::now();
                let found = loop {
                    let s = w.run(&["room", "sessions", room, "--node", PERSON, "--json"]);
                    let id = s
                        .said
                        .lines()
                        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                        .find(|v| v["harness"] == "claude" && v["open"] == true)
                        .and_then(|v| v["id"].as_str().map(str::to_owned));
                    if id.is_some() || t0.elapsed() > Duration::from_secs(90) {
                        break id.ok_or(s.said);
                    }
                    std::thread::sleep(Duration::from_millis(500));
                };
                match found {
                    Err(said) => {
                        l.claim("J6.drive.found", false, || format!("within 90 s of a prompt typed in Claude Code, the person found no open Claude Code Session: {said}"));
                        for c in ["said", "renamed", "while_waiting"] {
                            l.cannot(&format!("J6.drive.{c}"), "no open Session found");
                        }
                    }
                    Ok(sid) => {
                        l.claim("J6.drive.found", true, String::new);
                        // The person drives once the agent is idle, as its Session shows.
                        let t0 = Instant::now();
                        while t0.elapsed() < Duration::from_secs(60)
                            && !w
                                .run(&["room", "session", room, &sid, "--node", PERSON])
                                .said
                                .trim_end()
                                .ends_with("— turn ended —")
                        {
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        let token = format!("driven-from-vox-{}", std::process::id());
                        let before = sent_len();
                        let d = w.run(&[
                            "room", "session", room, &sid, "--node", PERSON, "--say", &token,
                        ]);
                        let t0 = Instant::now();
                        let reached = loop {
                            let all = std::fs::read_to_string(&log).unwrap_or_default();
                            if all.lines().skip(before).any(|l| l.contains(&token)) {
                                break true;
                            }
                            if t0.elapsed() > Duration::from_secs(60) {
                                break false;
                            }
                            std::thread::sleep(Duration::from_millis(500));
                        };
                        let session_said = w
                            .run(&["room", "session", room, &sid, "--node", PERSON])
                            .said;
                        l.claim("J6.drive.said", d.ok && reached, || {
                            format!(
                                "the person drove `--say {token}`, which said {:?}; Claude Code's \
                                 model got it: {reached}; the Session reads:\n{}\nthe pane:\n{}",
                                d.said.trim(),
                                last_lines(&session_said, 12),
                                screen()
                            )
                        });
                        let r = w.run(&[
                            "room",
                            "session",
                            room,
                            &sid,
                            "--node",
                            PERSON,
                            "--slash",
                            "/rename journey-frogs",
                        ]);
                        let t0 = Instant::now();
                        let shown = loop {
                            let s = w.run(&["room", "sessions", room, "--node", PERSON]);
                            if s.said.contains("journey-frogs") {
                                break Ok(());
                            }
                            if t0.elapsed() > Duration::from_secs(10) {
                                break Err(s.said);
                            }
                            std::thread::sleep(Duration::from_millis(500));
                        };
                        l.claim("J6.drive.renamed", r.ok && shown.is_ok(), || {
                            format!("a `/rename journey-frogs` driven from Vox (it said {:?}) was not shown within 10 s: {:?}", r.said.trim(), shown.err())
                        });
                        // **Driving a session that waits on an approval**: its model asks to run
                        // a command, and Claude Code waits on the person's approval. What the
                        // person types from Vox then is either handed to the session's model, or
                        // refused with the reason; never said delivered and lost.
                        std::fs::write(&run_file, "vox agent status --harness claude")
                            .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
                        let _ = tm(&["send-keys", "-t", ":0.0", "-l", "check vox"]);
                        std::thread::sleep(Duration::from_millis(600));
                        let _ = tm(&["send-keys", "-t", ":0.0", "Enter"]);
                        let t0 = Instant::now();
                        let waiting = loop {
                            // Claude Code's own approval prompt, on its screen.
                            if screen().contains("Do you want to proceed?") {
                                break true;
                            }
                            if t0.elapsed() > Duration::from_secs(60) {
                                break false;
                            }
                            std::thread::sleep(Duration::from_millis(500));
                        };
                        if !waiting {
                            l.apparatus(
                                "J6.drive.while_waiting",
                                &format!("Claude Code never waited on an approval for the stand-in's command; the pane:\n{}", screen()),
                            );
                        } else {
                            let token = format!("driven-while-waiting-{}", std::process::id());
                            let before = sent_len();
                            let d = w.run(&[
                                "room", "session", room, &sid, "--node", PERSON, "--say", &token,
                            ]);
                            let t0 = Instant::now();
                            let reached = loop {
                                let all = std::fs::read_to_string(&log).unwrap_or_default();
                                if all.lines().skip(before).any(|l| l.contains(&token)) {
                                    break true;
                                }
                                if !d.ok || t0.elapsed() > Duration::from_secs(60) {
                                    break false;
                                }
                                std::thread::sleep(Duration::from_millis(500));
                            };
                            let session_said = w
                                .run(&["room", "session", room, &sid, "--node", PERSON])
                                .said;
                            l.claim("J6.drive.while_waiting", reached || !d.ok, || {
                                format!(
                                    "with an approval pending, the person drove `--say {token}`; Vox said {:?}, \
                                     and the session's model never got it within 60 s; the Session reads:\n{}\n\
                                     the pane:\n{}",
                                    d.said.trim(),
                                    last_lines(&session_said, 8),
                                    screen()
                                )
                            });
                        }
                    }
                }
            }
            let _ = tm(&["kill-server"]);
        } else {
            for c in ["found", "said", "renamed", "while_waiting"] {
                l.cannot(
                    &format!("J6.drive.{c}"),
                    "Claude Code's session never worked in the room, or the person has no drive",
                );
            }
        }

        // ================================================================ 7. restart, update
        let stopped = w.stop_daemon();
        if !stopped {
            l.apparatus(
                "J7.restart.attached",
                "the daemon did not stop within 30 s of SIGTERM",
            );
        } else {
            // The machine comes back: `vox daemon` starts as the app's login item starts it, and
            // nothing is typed.
            let log = std::fs::File::create(w.root.join("daemon.log"))
                .unwrap_or_else(|e| panic!("APPARATUS: the daemon's log: {e}"));
            let daemon = Command::new(w.vox())
                .arg("daemon")
                .env_clear()
                .envs(w.env())
                .stdin(Stdio::null())
                .stdout(Stdio::from(
                    log.try_clone().unwrap_or_else(|e| panic!("APPARATUS: {e}")),
                ))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox daemon: {e}"));
            stop.children.push(daemon);
            let up = Out {
                ok: true,
                said: "vox daemon started, as the app's login item starts it".into(),
                took: Duration::ZERO,
            };
            let t0 = Instant::now();
            let (attached, said) = loop {
                let (a, s) = w.attached(&nodes);
                if a.len() == nodes.len() || t0.elapsed() > Duration::from_secs(30) {
                    break (a, s);
                }
                std::thread::sleep(Duration::from_millis(500));
            };
            l.claim("J7.restart.attached", attached.len() == nodes.len(), || {
                format!("after the daemon restarted (`vox up` said {:?}), attached: {attached:?} of {nodes:?}:\n{said}", last_lines(&up.said, 2))
            });
        }
        let update = w.run(&["update"]);
        println!("[journey] 7. vox update said:\n{}", indent(&update.said));
        l.claim(
            "J7.update.ok",
            update.ok && !update.said.to_ascii_lowercase().contains("passphrase:"),
            || {
                format!(
                    "`vox update`, at no terminal, must finish asking nothing:\n{}",
                    last_lines(&update.said, 10)
                )
            },
        );
        let t0 = Instant::now();
        let (attached, said) = loop {
            let (a, s) = w.attached(&nodes);
            if a.len() == nodes.len() || t0.elapsed() > Duration::from_secs(30) {
                break (a, s);
            }
            std::thread::sleep(Duration::from_millis(500));
        };
        l.claim("J7.update.attached", attached.len() == nodes.len(), || {
            format!("after `vox update`, attached: {attached:?} of {nodes:?}:\n{said}\nthe update ended:\n{}", last_lines(&update.said, 6))
        });
        let entry = w.run(&["agent", "skill"]).said;
        let stale: Vec<&str> = HARNESSES
            .iter()
            .filter(|(k, _, _)| {
                let f = std::fs::read_to_string(pack_in(&w.home, k).join("SKILL.md"))
                    .unwrap_or_default();
                f.is_empty() || !entry.starts_with(f.trim_end())
            })
            .map(|(k, _, _)| *k)
            .collect();
        l.claim("J7.update.pack", stale.is_empty(), || {
            format!(
                "after `vox update`, the skill pack is missing or not this version's for {stale:?}"
            )
        });
        let wrong = wired("after the update");
        l.claim("J7.update.hooks", wrong.is_empty(), || format!("{wrong:?}"));
        l.claim("J8.update", names_next_action(&update.said), || {
            format!(
                "`vox update`'s last lines name no next action:\n{}",
                last_lines(&update.said, 3)
            )
        });
        for h in &harnesses {
            let id = format!("J7.{}.ready", h.key);
            if !ready.get(h.key).copied().unwrap_or(false) {
                l.cannot(&id, "the harness's session never worked in the room");
                continue;
            }
            match session(h, "") {
                Ok((_, said)) => {
                    l.claim(&id, said.contains("works in room"), || {
                        format!("after the restart and the update, {}'s next session did not work in the room with nothing retyped:\n{}", h.name, last_lines(&said, 10))
                    });
                }
                Err(why) => l.apparatus(&id, &why),
            }
        }

        // ================================================================ 9. every hook path
        let hook_cmd = |file: &Path| -> Option<String> {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
            let mut s = String::new();
            strings_of(&v, &mut s);
            s.lines()
                .find(|l| l.contains("vox agent hook") && l.contains("--node"))
                .map(str::to_owned)
        };
        let wirings = [
            ("claude", hook_cmd(&w.home.join(".claude/settings.json"))),
            ("codex", hook_cmd(&w.home.join(".codex/hooks.json"))),
        ];
        let hook = |cmd: &str| -> (Duration, String) {
            let input = serde_json::json!({
                "session_id": "0a0a0a0a-1111-4222-8333-944444444444",
                "transcript_path": w.root.join("t/transcript.jsonl").display().to_string(),
                "cwd": w.repo.display().to_string(),
                "hook_event_name": "UserPromptSubmit",
                "prompt": "hello",
            })
            .to_string();
            let t0 = Instant::now();
            let mut c = Command::new("/bin/sh")
                .args(["-c", cmd])
                .env_clear()
                .envs(w.env())
                .current_dir(&w.repo)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| panic!("APPARATUS: cannot run the hook: {e}"));
            if let Some(mut i) = c.stdin.take() {
                let _ = i.write_all(input.as_bytes());
            }
            let out = c
                .wait_with_output()
                .unwrap_or_else(|e| panic!("APPARATUS: the hook: {e}"));
            let took = t0.elapsed();
            let raw = String::from_utf8_lossy(&out.stdout).into_owned();
            let text = match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(mut v) => {
                    if let Some(o) = v
                        .get_mut("hookSpecificOutput")
                        .and_then(|o| o.as_object_mut())
                    {
                        o.remove("hookEventName");
                    }
                    let mut s = String::new();
                    strings_of(&v, &mut s);
                    s
                }
                Err(_) => raw,
            };
            (took, text.trim().to_owned())
        };
        let mut paths: Vec<(&str, String, &str)> = Vec::new();
        for (key, cmd) in &wirings {
            match cmd {
                Some(c) => {
                    let node = HARNESSES
                        .iter()
                        .find(|h| h.0 == *key)
                        .map(|h| h.2)
                        .unwrap_or_default();
                    paths.push(("detached", c.clone(), node));
                    paths.push(("no-daemon", c.clone(), node));
                    paths.push(("no-node", c.replace(node, &format!("{node}-gone")), node));
                }
                None => {
                    for p in ["detached", "no-daemon", "no-node"] {
                        l.cannot(
                            &format!("J9.{key}.{p}"),
                            "setup wrote no `vox agent hook` command for it",
                        );
                    }
                }
            }
        }
        for (path, cmd, node) in &paths {
            let key = if cmd.contains("claude-mine") {
                "claude"
            } else {
                "codex"
            };
            match *path {
                "detached" => {
                    // A daemon running, holding the person's node, and this one detached.
                    let _ = w.person(&["node", "attach", PERSON], PERSON);
                    let _ = w.run(&["node", "detach", node]);
                }
                "no-daemon" => {
                    w.stop_daemon();
                }
                _ => {}
            }
            let (took, text) = hook(cmd);
            println!(
                "[journey] 9. {key} hook, {path}: {:.0} ms: {text:?}",
                took.as_secs_f64() * 1000.0
            );
            l.claim(
                &format!("J9.{key}.{path}.fast"),
                took < Duration::from_secs(1),
                || {
                    format!(
                        "the hook took {:.0} ms ({path}); it said {text:?}",
                        took.as_secs_f64() * 1000.0
                    )
                },
            );
            let guides = told_command(&text).is_some() || text.contains("vox ");
            l.claim(&format!("J9.{key}.{path}.one_sentence"), sentences(&text) == 1 && guides, || {
                format!(
                    "the hook must give one sentence of guidance, naming what to do ({path}); it gave \
                     {} sentence(s){}: {text:?}",
                    sentences(&text),
                    if guides { "" } else { " naming nothing to do" }
                )
            });
        }
        drop(server);
        drop(stop);
        l.finish();
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional heavy proof, required before every release tag: the whole fresh-user journey, \
            with Claude Code, Codex and OpenCode against a stand-in model"]
fn a_fresh_user_gets_from_install_to_an_agent_working_in_a_room() {
    journey::run();
}
