//! ADR-020 §6 / M19.5b — the OpenCode plugin, driven by a **real model**.
//!
//! This is the proof M19.5 could not write. `agent_hook_proof.rs` proves the hook
//! emits the right shape for Claude Code and Codex, and says so in its own header:
//! it could **not** confirm that a harness shows the model what it injects, because
//! the machine's API key returned 401 and no model ever ran. "The JSON has the
//! documented shape" and "the model read it" are different claims, and only the
//! second is the product working.
//!
//! So this test asserts the second one. It posts a codeword into a real Vox room,
//! starts a real node, installs the real plugin, runs a real `opencode` turn against
//! a real model, and requires the **model's own answer** to contain the codeword —
//! a token that appears nowhere in the prompt, nowhere in the plugin and nowhere in
//! OpenCode.
//!
//! ## The mutation check is built into the harness
//!
//! `opencode run --pure` runs without external plugins. Same room, same prompt,
//! plugin disabled: the codeword **must vanish**. That is not a check bolted on
//! afterwards — it is the same binary being asked the same question with the one
//! thing under test removed, which is what [[vox-gates-can-assert-the-bug]] demands
//! and what a green-on-first-run gate never earns.
//!
//! ## What was measured, not read
//!
//! OpenCode's plugin API is not publicly documented. Against 1.18.31:
//!
//! - `chat.message(input, output)` fires per user message and `output.parts` is what
//!   the model is about to be shown.
//! - **Rewriting an existing text part works. Appending a new part does not** — it
//!   hangs the turn indefinitely, with and without a completed `time` field, and
//!   prints nothing on either stream.
//! - A part id must start with `prt`, or the whole turn dies with a `SchemaError`
//!   surfacing as an `UnknownError` that names nothing useful.
//!
//! ## Honest coverage
//!
//! ## Every participant is the shipped binary
//!
//! The node is a real `vox daemon` holding a profile made as a person makes one — `vox id`,
//! `vox daemon`, `vox room create` (passphrase on stdin) — and the codeword is posted with
//! `vox room post`. The plugin is what `vox agent plugin opencode` prints, installed where a
//! person puts it. Nothing in this process runs a node.
//!
//! ## The product mutation
//!
//! `--pure` removes the plugin from the harness; it does not break the product. So the proof
//! is also run against a `vox` whose `vox agent hook` injects nothing (the drain returns
//! before printing what is unread): the codeword must not reach the model, and the proof
//! goes red as `PRODUCT: the room never reached the model: the plugin said "…chat.message:
//! nothing to inject"`, whatever the model answers. The verdict is read from the plugin's own
//! log of that turn: injected and repeated is green; injected and not repeated, or no
//! `chat.message` at all, is CANNOT MEASURE.
//!
//! ## A plain `opencode`, opened by hand, can be interrupted (ADR-020 §6, ADR-021 F17)
//!
//! The same daemon, room and installed plugin, then what a person does: open `opencode` in
//! the project with **no flags** — `VOX_ROOM` and `VOX_AGENT_NAME` exported, nothing else —
//! in a pty, and ask it for a turn that runs `sleep`. While the tool runs, they post an urgent
//! message addressed to someone else, then one addressed to this agent. The work is in
//! `tests/pty/opencode_wake.py` (the screen read through `pyte`); this asserts what it saw:
//!
//! 1. the session's own drain registered it with the daemon as **OpenCode, reachable** (the
//!    plugin's wake socket), as `vox agent doctor --json` lists it — a plain `opencode` has no
//!    listener of its own, and before F17 it registered as `unknown`;
//! 2. the message addressed to someone else **never reaches the screen** while the turn runs;
//! 3. the one addressed to this agent **reaches the screen mid-turn**, before the tool ends;
//! 4. and the tool that was running **still runs to its end** (its output reaches the screen):
//!    the interrupt queues into the running turn, never aborts it.
//!
//! Then, once the turn the wake started has answered, what the model was **given** — the
//! session's user messages as OpenCode stored them, after the plugin rewrote them (V210-112):
//!
//! 5. the message that woke it appears **once**, in the `<vox-room>` read of the turn the wake
//!    started: the wake is a notice carrying no message (V030-15); and the one addressed to
//!    someone else, which woke nothing, appears exactly once, in that read;
//! 6. and every message is shown as its words, never as its envelope JSON.
//!
//! Mutation-checked: `vox agent hook` not registering the plugin's socket (the session stays
//! `unknown`) goes red at (1) and (3); the plugin taking the wake and never relaying it goes
//! red at (3); the message put back in the wake goes red at (5); the text format printing
//! a message's raw envelope goes red at (6).
//!
//! ## The wake directory goes with the session, however the person quits (ADR-021 F17)
//!
//! The plugin's socket lives in a `vox-oc-*` directory of the temp directory. Every OpenCode in
//! this proof runs with this run's own `TMPDIR`, so the directories counted are exactly its own.
//! The person quits that session by closing its terminal (SIGHUP), then opens three more plain
//! `opencode`s:
//!
//! 7. each quit — terminal closed, ctrl+C, `/exit` — **removes that session's directory**;
//! 8. one SIGKILLed together with the helper that removes its directory leaves it, as a crash
//!    does, and **the next `opencode` opened removes it**;
//! 9. after every OpenCode of the run has exited, **no `vox-oc-*` is left** in its `TMPDIR`.
//!
//! Mutation-checked: no cleanup helper goes red at (7); no sweep at start goes red at (8).
//!
//! ## Every OpenCode here is sandboxed
//!
//! A model's turn may run a shell. Unconfined, a free model's shell read the operator's files
//! (`~/.claude`, `~/.codex`, `~/.config`, other agents' scratch directories) and sent what it
//! found to its provider. So every OpenCode this proof starts, `opencode run` and the pty
//! sessions alike, runs under macOS `sandbox-exec` with a whitelist of readable paths (the
//! system, the OpenCode and `vox` binaries, the run's sandbox root) and a throwaway HOME. The
//! plugin-fed turns may also read the run's own vox profile, which the plugin's hook needs;
//! the `--pure` control may not. Before any model runs, a shell in the sandbox must fail to
//! read or find a canary file planted in the operator's real HOME, and no OpenCode's output
//! may ever hold the canary: either is APPARATUS, and stops the run. The sandbox holds a copy of
//! OpenCode's own provider credential alone, removed when the run ends; the operator's other
//! providers' keys never enter it. What a run leaves outside itself (the canary, the copy) is
//! removed on every exit, an abort or a signal included, and a SIGKILLed run's at the next
//! run's start. No red, and nothing sent to a model, names a real path: the canary-read turn
//! names a link in the project.
//!
//! **Known limit:** the plugin and the model's shell run in one sandbox, so the shell could write
//! the plugin's log, which the codeword verdict reads. A tighter sandbox for the shell alone is
//! not possible: macOS refuses a sandbox inside a sandbox (`sandbox_apply: Operation not
//! permitted`, measured). Forging it takes a model set on deceiving the proof, not one exploring.
//! Likewise a model that ran `ls -l` on the link would see the canary's real path.
//!
//! OpenCode absent, or no usable credential, fails as **CANNOT MEASURE** — an absent prover is
//! missing evidence, not evidence of correctness.

// Optional (decider, 2026-10-01; live-model proofs are ad hoc and on demand, 2026-10-02): it
// blocks nothing and CI only compiles it. Without `--features optional-proofs` a stand-in takes
// its place and says it was not run (`support/optional_proof.rs`). How to run it:
// docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_real_model_reads_the_room_through_the_opencode_plugin);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";

/// Cheap and fast; overridable because pinning a model name in a test is brittle.
fn model() -> String {
    oc_sandbox::model()
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `vox` against this profile, with `input` piped to stdin when given.
/// A path as the pty driver's argument.
fn path_arg(p: &Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("APPARATUS: this run's path {p:?} is not UTF-8"))
}

fn vox(data: &Path, cfg: &Path, args: &[&str], input: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        // The data root holds a second node, carol's (see `carol`): every verb here is bob's.
        .env("VOX_NODE", "default")
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
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox {}`: {e}", args.join(" ")));
    if let Some(text) = input {
        let mut pipe = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("APPARATUS: `vox {}` has no stdin pipe", args.join(" ")));
        // A write that fails (EPIPE) means `vox` exited without reading its input: that is
        // the product's outcome, which the caller judges by its exit and what it printed.
        let _ = pipe.write_all(text.as_bytes());
        drop(pipe);
    }
    let out = child.wait_with_output().unwrap_or_else(|e| {
        panic!(
            "APPARATUS: cannot collect `vox {}`'s output: {e}",
            args.join(" ")
        )
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// **Someone else in the room** for the hand-opened session's "addressed to someone else": a
/// message is addressed to a node, so it is another member's node — carol's, a second node in this
/// data root on the same daemon, joined to the room. Its fingerprint.
fn carol(data: &Path, cfg: &Path, room: &str, tmp: &Path) -> String {
    let (ok, _, err) = vox(data, cfg, &["node", "create", "carol"], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox node create carol` refused: {err}"
    );
    let pass = tmp.join("carol.pass");
    std::fs::write(&pass, format!("{IDENTITY}\n"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write carol's passphrase file: {e}"));
    let (ok, _, err) = vox(
        data,
        cfg,
        &[
            "node",
            "attach",
            "carol",
            "--passphrase-file",
            path_arg(&pass),
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): `vox node attach carol` refused: {err}"
    );
    let (ok, invite, err) = vox(data, cfg, &["room", "link", room], None);
    let address = invite
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): `vox room link` printed no address: {invite:?} {err} ({ok})")
        })
        .to_owned();
    let (ok, _, err) = vox(
        data,
        cfg,
        &[
            "room",
            "join",
            "--node",
            "carol",
            "--passphrase-file",
            "-",
            &address,
        ],
        Some("channel passphrase\n"),
    );
    assert!(
        ok,
        "PRODUCT (staging): carol's `vox room join` refused: {err}"
    );
    let (_, roster, _) = vox(data, cfg, &["room", "roster", room], None);
    let (_, own, _) = vox(data, cfg, &["id"], None);
    roster
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 52 && *l != own.trim())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the roster does not list carol: {roster:?}"))
        .to_owned()
}

/// Run one `opencode` turn, confined by `sb` under `profile`, and return its stdout.
fn opencode_turn(
    project: &Path,
    env: &[(&str, &std::ffi::OsStr)],
    pure: bool,
    prompt: &str,
    sb: &oc_sandbox::OcSandbox,
    profile: &Path,
) -> String {
    let mut cmd = sb.opencode(profile, &[], project);
    // **A cleared environment, not an inherited one** (`OcSandbox::opencode`): run from a shell
    // the plugin works; run from `cargo test` with the same directory and arguments it loads and
    // its `chat.message` hook never fires.
    cmd.arg("run");
    if pure {
        cmd.arg("--pure");
    }
    cmd.args(["-m", &model()]).arg(prompt);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run opencode: {e}"));
    // stderr is carried back with stdout: the plugin inherits `vox agent hook`'s
    // stderr, which is where a broken setup says so. A proof that hides the one
    // channel carrying the diagnosis wastes the run it just paid for.
    let said = format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    sb.check(&said, "an `opencode run` turn");
    // **A model that would not answer measures nothing.** A provider refusing the turn (no
    // funds, a rate limit, a bad key, an overloaded or unknown model) leaves no answer to judge,
    // so every verdict after it would read as the plugin's. Say so, with the provider's words.
    if let Some(line) = oc_sandbox::provider_failure(&said) {
        panic!(
            "APPARATUS, CANNOT MEASURE: the model provider refused the turn ({}): {line}",
            model()
        );
    }
    said
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a real model through a real harness; optional, run it in release"]
fn a_real_model_reads_the_room_through_the_opencode_plugin() {
    // Five or six real model turns, one of them a 45 s tool, plus the pty driver's own bound.
    watchdog::arm_for(Duration::from_secs(900));

    if !oc_sandbox::live_model_allowed(
        "opencode_plugin_proof::a_real_model_reads_the_room_through_the_opencode_plugin",
    ) {
        return;
    }
    assert!(
        which("opencode").is_some(),
        "APPARATUS, CANNOT MEASURE: opencode is not installed, so nothing here can be tested against a real \
         harness"
    );

    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");

    // ---- a real daemon, a real room, and a codeword only the room knows ----
    let (ok, fp, err) = vox(&data, &cfg, &["id"], None);
    assert!(
        ok && fp.trim().len() == 52,
        "PRODUCT: `vox id` did not make an identity: {fp:?} {err}"
    );
    let _daemon = Daemon(
        Command::new(VOX)
            .args(["daemon", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &data)
            .env("VOX_CONFIG_DIR", &cfg)
            .env_remove("VOX_ROOM")
            .stdin({
                let pass = tmp.path().join("identity.pass");
                std::fs::write(&pass, format!("{IDENTITY}\n"))
                    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the passphrase file: {e}"));
                Stdio::from(
                    std::fs::File::open(&pass).unwrap_or_else(|e| {
                        panic!("APPARATUS: cannot open the passphrase file: {e}")
                    }),
                )
            })
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(tmp.path().join("daemon.err"))
                    .unwrap_or_else(|e| panic!("APPARATUS: cannot make daemon.err: {e}")),
            ))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox daemon`: {e}")),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(&data, &cfg, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never answered; its stderr: {:?}",
            std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        Some("channel passphrase\n"),
    );
    assert!(ok, "PRODUCT: `vox room create` refused: {err}");
    let (_, list, _) = vox(&data, &cfg, &["room", "list"], None);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` does not show the new room: {list:?}"))
        .to_owned();

    // Unique per run, so a cached session cannot produce it and neither can a model
    // that has seen this file. Shaped to survive a model repeating it verbatim.
    let codeword = format!(
        "QUXNARB-{:04}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
            .subsec_millis()
    );
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "post",
            &room,
            &format!("The codeword for this mission is {codeword}."),
        ],
        None,
    );
    assert!(ok, "PRODUCT: `vox room post` refused: {err}");
    let carol = carol(&data, &cfg, &room, tmp.path());
    println!("[proof] room {room} holds codeword {codeword}, posted through `vox room post`");

    // Isolate OpenCode's **configuration**, so the operator's own plugins, model
    // and provider settings cannot decide whether this passes.
    //
    // Two things here were measured, and both cost a run to find:
    //
    // 1. **`$XDG_CONFIG_HOME/opencode/` must exist.** Point `XDG_CONFIG_HOME` at a
    //    directory without it and OpenCode loads the plugin — its init runs — but
    //    **`chat.message` never fires** and the turn produces no output at all. The
    //    failure is indistinguishable from a plugin that does not work.
    // 2. **`XDG_DATA_HOME` is deliberately left alone.** It holds more than the
    //    credential, and overriding it produced the same silent failure. Since the
    //    project directory is a fresh temp dir, any session written to the real data
    //    dir is tied to a path that ceases to exist, and nothing of the operator's
    //    is touched.
    // ---- the sandbox every OpenCode here runs in (support/oc_sandbox.rs) ----
    // Its root holds everything an OpenCode of this run may touch: the fixture, its TMPDIR,
    // the plugin's log, a throwaway HOME. The run's vox profile stays outside it, readable
    // only by the plugin-fed turns, whose hook needs it. Each profile is probed against the
    // canary before any model runs under it.
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    let sb_root = sb.root.clone();
    let fed_profile = sb.profile("fed", &[&data, &cfg], &[Path::new(VOX)]);
    let pure_profile = sb.profile("pure", &[], &[]);

    let plugin_log = sb_root.join("plugin.log");
    // **This run's own fixture**, so two runs at once never share a project. OpenCode
    // installs a `node_modules` tree into `.opencode/` in the project and
    // `$XDG_CONFIG_HOME/opencode/` the first time it is used there, and until it has, the
    // plugin may load while its `chat.message` never fires: the warm-up turns below take
    // the fresh project through that, to the state any real project is in after its first
    // turn.
    let fixture = sb_root.join("oc");
    let oc_cfg = fixture.join("config");
    let project = fixture.join("project");
    for d in [oc_cfg.join("opencode"), project.join(".opencode/plugin")] {
        std::fs::create_dir_all(&d)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make the fixture's {d:?}: {e}"));
    }
    // What a plain `opencode` (no `-m`) runs with: the model, and a shell tool it may use
    // without asking — the interrupt case needs a turn that is busy running one.
    std::fs::write(
        project.join("opencode.json"),
        serde_json::json!({
            "$schema": "https://opencode.ai/config.json",
            "model": model(),
            "permission": { "bash": "allow" }
        })
        .to_string(),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the fixture's opencode.json: {e}"));

    // Every OpenCode here runs with this run's own `TMPDIR`, where its plugin makes its wake
    // directory: (9) counts exactly this run's. Short, because a Unix socket's path is.
    let oc_tmp = sb_root.join("t");
    std::fs::create_dir_all(&oc_tmp)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make this run's TMPDIR {oc_tmp:?}: {e}"));
    let wake_dirs = || {
        std::fs::read_dir(&oc_tmp)
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().starts_with("vox-oc-"))
                    .map(|e| e.path().display().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    println!(
        "[proof] vox-oc-* in this run's TMPDIR before it: {}",
        wake_dirs().len()
    );
    let env: Vec<(&str, &std::ffi::OsStr)> = vec![
        ("TMPDIR", oc_tmp.as_os_str()),
        ("XDG_CONFIG_HOME", oc_cfg.as_os_str()),
        ("VOX_DATA_DIR", data.as_os_str()),
        ("VOX_CONFIG_DIR", cfg.as_os_str()),
        ("VOX_ROOM", std::ffi::OsStr::new(room.as_str())),
        ("VOX_BIN", std::ffi::OsStr::new(VOX)),
        ("VOX_PLUGIN_LOG", plugin_log.as_os_str()),
    ];
    let plugin_diag = |label: &str| {
        std::fs::read_to_string(&plugin_log)
            .map(|s| format!("\n--- plugin log ({label}) ---\n{s}"))
            .unwrap_or_else(|_| format!("\n--- plugin log ({label}): NEVER WROTE ---"))
    };
    let prompt = "What is the codeword for this mission? Answer with just the codeword.";

    // ---- the sandbox holds against a model told to break it ----
    // The first turn of the run asks the model, in the more open of the two sandboxes, to read
    // the canary and print it. Whatever it does, the canary must not come back (`opencode_turn`
    // checks every turn's output for it).
    // The prompt names a link in the project, never the real path: what a model is sent goes
    // to its provider. (`cat` follows the link; the sandbox refuses the canary's real path.)
    let link = project.join("canary.txt");
    std::os::unix::fs::symlink(&sb.canary.path, &link)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot link the canary into the project: {e}"));
    let told = opencode_turn(
        &project,
        &env,
        true,
        "Use your shell to run `cat canary.txt` in the current directory, and print exactly \
         what it printed.",
        &sb,
        &fed_profile,
    );
    let _ = std::fs::remove_file(&link);
    println!(
        "[proof] a model told to read the canary in the real HOME: it did not come back ({} \
         bytes of answer)",
        told.len()
    );

    // ---- the control: the same turn with the plugin disabled ----
    // `--pure` removes external plugins, so the codeword must be out of the model's reach. It is
    // run **first**, before any turn the plugin has fed, and with an empty vox profile and no
    // room: a model with a shell otherwise found the codeword without the plugin (a free model
    // listed the run's files and read it back), through `vox room read` on the run's daemon or
    // an earlier session's transcript. Denying the shell is not an option: the free tier refuses
    // any turn whose shell is denied (measured, opencode 1.18.34).
    let bare = sb_root.join("bare");
    for d in [bare.join("data"), bare.join("cfg")] {
        std::fs::create_dir_all(&d)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make the control's {d:?}: {e}"));
    }
    let (bare_data, bare_cfg) = (bare.join("data"), bare.join("cfg"));
    let control_env: Vec<(&str, &std::ffi::OsStr)> = vec![
        ("TMPDIR", oc_tmp.as_os_str()),
        ("XDG_CONFIG_HOME", oc_cfg.as_os_str()),
        ("VOX_DATA_DIR", bare_data.as_os_str()),
        ("VOX_CONFIG_DIR", bare_cfg.as_os_str()),
    ];
    let without = opencode_turn(&project, &control_env, true, prompt, &sb, &pure_profile);
    println!(
        "[proof] with --pure, the model's answer contains the codeword: {}",
        without.contains(&codeword)
    );
    assert!(
        !without.contains(&codeword),
        "APPARATUS, CANNOT MEASURE: `--pure` disables external plugins, so the codeword must be \
         unreachable; it still appears, so this run is not measuring the plugin. Got: {without:?}"
    );

    // **Warm the project directory first.** OpenCode installs a `node_modules` tree
    // into `.opencode/` the first time it is used in a directory, and during that
    // first run the plugin is loaded but its `chat.message` hook never fires — the
    // turn answers with no injection at all. A real operator hits this once, in a
    // repository they then keep using; a test that makes a fresh temp directory
    // every run would hit it *every* time and conclude the plugin does not work,
    // which is exactly what happened here for several runs.
    //
    // This is not a workaround for a defect in the plugin. It reproduces the state
    // every real project is in by its second turn.
    let (ok, plugin, err) = vox(
        &data,
        &cfg,
        &["agent", "plugin", "opencode", "--node", "default"],
        None,
    );
    assert!(
        ok && plugin.contains("vox agent hook"),
        "PRODUCT: `vox agent plugin opencode` did not print the plugin: {err}"
    );
    std::fs::write(project.join(".opencode/plugin/vox.js"), plugin)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot install the plugin in the fixture: {e}"));
    for attempt in 0..3 {
        let _ = opencode_turn(
            &project,
            &env,
            false,
            "Reply with exactly: READY",
            &sb,
            &fed_profile,
        );
        if std::fs::read_to_string(&plugin_log)
            .map(|l| l.contains("chat.message"))
            .unwrap_or(false)
        {
            break;
        }
        if attempt == 2 {
            // Vox's plugin never loading is the product's; loaded, with OpenCode never
            // calling its hook in this fresh project, is OpenCode's state, not a verdict.
            let loaded =
                std::fs::read_to_string(&plugin_log).is_ok_and(|l| l.contains("plugin loaded"));
            panic!(
                "{}{}",
                if loaded {
                    "APPARATUS, CANNOT MEASURE: the plugin loaded, but OpenCode never fired `chat.message` \
                     in three warm-up turns, so the plugin's seam could not be exercised"
                } else {
                    "PRODUCT: OpenCode never loaded the plugin `vox agent plugin opencode` \
                     printed, in three warm-up turns"
                },
                plugin_diag("warm-up")
            );
        }
    }
    let _ = std::fs::write(&plugin_log, "");

    // ---- the proof: a real model repeats something only the room told it ----
    let answer = opencode_turn(&project, &env, false, prompt, &sb, &fed_profile);
    println!(
        "[proof] with the plugin, the model's answer contains the codeword: {}",
        answer.contains(&codeword)
    );
    // **The verdict is what the plugin's own log says it did on this turn**, not the answer
    // alone: a model with a shell may find the codeword itself, and may decline to repeat it.
    let log = std::fs::read_to_string(&plugin_log).unwrap_or_default();
    let hooked: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("chat.message:"))
        .collect();
    let said_of = |what: &str| hooked.iter().find(|l| l.contains(what)).copied();
    let has_codeword = answer.contains(&codeword);
    if said_of("chat.message: injected").is_some() {
        assert!(
            has_codeword,
            "APPARATUS, CANNOT MEASURE: the plugin injected the room, and the model did not repeat it. \
             Expected {codeword:?} in the model's answer, got: {answer:?}{}",
            plugin_diag("with plugin")
        );
    } else if let Some(line) = said_of("nothing to inject")
        .or_else(|| said_of("threw"))
        .or_else(|| said_of("no text part"))
    {
        // The hook ran and the plugin put nothing in front of the model: the product's,
        // whatever the model answered (it may have found the codeword itself).
        panic!(
            "PRODUCT: the room never reached the model: the plugin said {line:?}{}",
            plugin_diag("with plugin")
        );
    } else if let Some(line) = said_of("VOX_ROOM is unset") {
        panic!(
            "APPARATUS: the proof did not give OpenCode the room: the plugin said {line:?}{}",
            plugin_diag("with plugin")
        );
    } else {
        // No `chat.message` on this turn (or one with no session): OpenCode never asked the
        // plugin, so the product was not exercised.
        panic!(
            "APPARATUS, CANNOT MEASURE: OpenCode never called the plugin's chat.message on this turn ({}){}",
            if hooked.is_empty() {
                "no chat.message line".to_owned()
            } else {
                format!("it said {hooked:?}")
            },
            plugin_diag("with plugin")
        );
    }

    // ---- a plain `opencode`, opened by hand, interrupted mid-turn (F17) ----
    let _ = std::fs::write(&plugin_log, "");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/opencode_wake.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            path_arg(&data),
            path_arg(&cfg),
            &room,
            path_arg(&project),
            path_arg(&oc_cfg),
            path_arg(&plugin_log),
            path_arg(&oc_tmp),
            path_arg(&fed_profile),
            path_arg(&sb.home),
            "wake",
            &carol,
            fp.trim(),
        ],
    );
    let said = out.stdout.clone();
    sb.check(&said, "the hand-opened sessions' driver");
    eprintln!(
        "{said}\n[proof] the driver took {:?}; its last stage: {:?}{}",
        out.took,
        out.stage,
        plugin_diag("hand-opened")
    );
    // **The product's verdicts first, whatever the driver did next.** A line the driver printed
    // is what the person saw; judged only after the exit code, a plugin that made no wake
    // channel (so the driver could not go on) read as the apparatus's failure.
    let seen = |key: &str| {
        said.lines()
            .find_map(|l| l.strip_prefix(&format!("wake {key}: ")))
            .map(str::to_owned)
    };
    println!(
        "[proof] hand-opened `opencode`: registered {:?}; addressed to someone else: {:?}; \
         addressed to it: {:?}; its running turn: {:?}",
        seen("REGISTERED"),
        seen("OTHER"),
        seen("WAKE"),
        seen("TURN")
    );
    // As `vox agent doctor --json` lists the session: its harness, and whether its wake endpoint
    // (the plugin's socket) answers.
    if let Some(registered) = seen("REGISTERED") {
        assert!(
            registered == "opencode: its wake endpoint answers",
            "PRODUCT (1): a plain `opencode` must register as OpenCode, reachable through the \
             plugin's wake socket; `vox agent doctor` lists {registered:?}{}",
            plugin_diag("registration")
        );
    }
    if let Some(other) = seen("OTHER") {
        assert!(
            other == "absent",
            "PRODUCT (2): an urgent message addressed to someone else must not interrupt this \
             session; it was {other}: {said}"
        );
    }
    if let Some(wake) = seen("WAKE") {
        assert!(
            wake.starts_with("shown mid-turn"),
            "PRODUCT (3): an urgent message addressed to this session must interrupt it while its \
             turn runs; it was {wake}: {said}"
        );
    }
    if let Some(turn) = seen("TURN") {
        assert!(
            turn == "completed",
            "PRODUCT (4): the interrupt must queue into the running turn, not abort its tool; the \
             turn {turn}: {said}"
        );
    }
    if let Some(given) = seen("RECEIVED") {
        println!("[proof] what the model was given: {given}");
        let count = |key: &str| {
            given
                .split_whitespace()
                .find_map(|f| f.strip_prefix(&format!("{key}=")))
                .unwrap_or("(none)")
                .to_owned()
        };
        if given == "never" || count("woken") == "(none)" {
            panic!(
                "APPARATUS, CANNOT MEASURE: the turn the wake started never answered, so what the model was \
                 given could not be read: {said}"
            );
        }
        assert!(
            count("woken") == "1" && count("other") == "1",
            "PRODUCT (5): the message that woke the session must reach the model once — in the \
             room read, never in the wake, which carries no message — and the one that woke \
             nothing exactly once; the model was given woken={} other={}: {said}",
            count("woken"),
            count("other")
        );
        assert!(
            count("envelope") == "no",
            "PRODUCT (6): the room read must show each message as written, never as its envelope \
             JSON; envelope={}: {said}",
            count("envelope")
        );
    }
    // Only the plugin makes a wake directory, so a session that has none is the product's.
    if let Some(nodir) = seen("NODIR") {
        panic!(
            "PRODUCT (7): a plain `opencode`'s plugin made no wake directory: {nodir}{}",
            plugin_diag("no directory")
        );
    }
    match out.code {
        Some(0) => {}
        Some(2) => panic!("CANNOT MEASURE: the hand-opened session's apparatus failed: {said}"),
        _ if out.has_verdict("wake") => {
            panic!("APPARATUS, CANNOT MEASURE: the hand-opened session's driver hung or went red: {said}")
        }
        _ => panic!(
            "APPARATUS, CANNOT MEASURE: the hand-opened session's driver was stopped before it gave a \
             verdict, at stage {:?} (exit {:?}; its stack is above): {said}",
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
    }
    // The driver ran to its end (exit 0), so a line it did not print is the driver's fault.
    let line = |key: &str| {
        seen(key).unwrap_or_else(|| {
            panic!("APPARATUS: the driver exited 0 without its `wake {key}:` line: {said}")
        })
    };
    for key in ["REGISTERED", "OTHER", "WAKE", "TURN", "RECEIVED"] {
        line(key);
    }

    // ---- each session's wake directory goes with it (F17) ----
    for how in ["hup", "ctrl+c", "/exit"] {
        let quit = line(&format!("QUIT {how}"));
        println!("[proof] quit by {how}: its wake directory {quit}");
        assert!(
            quit.starts_with("removed "),
            "PRODUCT (7): a hand-opened `opencode` quit by {how} must take its wake directory with it; \
             it was {quit}{}",
            plugin_diag("quits")
        );
    }
    let swept = line("SWEPT");
    println!("[proof] killed with its cleanup, then another opened: its wake directory {swept}");
    assert!(
        swept.starts_with("removed "),
        "PRODUCT (8): the next `opencode` opened must remove a wake directory whose OpenCode was killed \
         with its cleanup; it was {swept}{}",
        plugin_diag("sweep")
    );
    let left = wake_dirs();
    println!(
        "[proof] vox-oc-* in this run's TMPDIR after it: {}",
        left.len()
    );
    assert!(
        left.is_empty(),
        "PRODUCT (9): no wake directory may outlive the OpenCode that made it; this run left {left:?}"
    );
}
