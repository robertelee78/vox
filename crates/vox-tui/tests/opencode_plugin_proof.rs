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
//! OpenCode absent, or no usable credential, is reported **unproven and fails** —
//! an absent prover is missing evidence, not evidence of correctness. Set
//! `VOX_PROOF_ALLOW_UNPROVEN=opencode` to accept that gap deliberately and visibly.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// Cheap and fast; overridable because pinning a model name in a test is brittle.
fn model() -> String {
    std::env::var("VOX_PROOF_OPENCODE_MODEL")
        .unwrap_or_else(|_| "opencode/claude-haiku-4-5".to_owned())
}

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

/// Where OpenCode keeps credentials. Copied into the test's own data dir so the run
/// is isolated from the operator's configuration **and** leaves nothing behind in
/// it — a proof that pollutes the machine it runs on is a bad neighbour.
fn auth_json() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))?;
    let p = base.join("opencode/auth.json");
    p.is_file().then_some(p)
}

/// Run one `opencode` turn and return its stdout.
fn opencode_turn(
    project: &Path,
    env: &[(&str, &std::ffi::OsStr)],
    pure: bool,
    prompt: &str,
) -> String {
    let mut cmd = Command::new("opencode");
    // **A cleared environment, not an inherited one.** Run from a shell the plugin
    // works; run from `cargo test` with the same directory and arguments it loads
    // and its `chat.message` hook never fires. Something cargo puts in the
    // environment disables plugin hooks, so the proof passes only what OpenCode
    // actually needs. This also makes the run reproducible: whatever the operator
    // happens to export cannot decide whether this passes.
    cmd.env_clear();
    for key in ["PATH", "HOME", "SHELL", "LANG", "TMPDIR", "USER"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.current_dir(project).arg("run");
    if pure {
        cmd.arg("--pure");
    }
    cmd.args(["-m", &model()]).arg(prompt);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run opencode");
    // stderr is carried back with stdout: the plugin inherits `vox agent hook`'s
    // stderr, which is where a broken setup says so. A proof that hides the one
    // channel carrying the diagnosis wastes the run it just paid for.
    format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
#[ignore = "drives a real model through a real harness; CI runs it in release"]
fn a_real_model_reads_the_room_through_the_opencode_plugin() {
    watchdog::arm();

    if which("opencode").is_none() {
        assert!(
            allow_unproven("opencode"),
            "UNPROVEN: opencode is not installed, so nothing here was tested against a real \
             harness. Install it, or set VOX_PROOF_ALLOW_UNPROVEN=opencode to accept the gap."
        );
        return;
    }
    let Some(auth) = auth_json() else {
        assert!(
            allow_unproven("opencode"),
            "UNPROVEN: no opencode auth.json, so no model can run. Authenticate opencode, or set \
             VOX_PROOF_ALLOW_UNPROVEN=opencode to accept the gap."
        );
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();

    // ---- a real node, a real room, and a codeword only the room knows ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let clock: Clock = Arc::new(|| 1_800_000_000);
    let node: NodeHandle = rt
        .block_on(async {
            Node::spawn_with(
                paths.clone(),
                clock,
                vox_core::atrest::sek::Argon2Profile::default(),
            )
        })
        .unwrap();

    // Unique per run, so a cached session cannot produce it and neither can a model
    // that has seen this file. Shaped to survive a model repeating it verbatim.
    let codeword = format!(
        "QUXNARB-{:04}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_millis()
    );

    let cid = rt.block_on(async {
        assert!(node
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(node
            .apply(NodeCommand::CreateChannel {
                local_name: "agents".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = node.view().channels[0].channel_id;
        assert!(node
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: format!("The codeword for this mission is {codeword}."),
            })
            .await
            .is_done());
        cid
    });
    let _server = rt
        .block_on(async { vox_core::node::ipc::bind(node.clone(), &paths) })
        .expect("bind");
    let room = vox_core::node::link::b32_encode(&cid);

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
    let plugin_log = tmp.path().join("plugin.log");
    // **A persistent fixture directory, not a fresh one per run.** OpenCode installs
    // a `node_modules` tree into BOTH `.opencode/` in the project and
    // `$XDG_CONFIG_HOME/opencode/`, and until both exist the plugin is loaded but
    // its `chat.message` hook never fires — the turn answers with no injection. A
    // fresh temp directory every run means that install never completes in time,
    // and the proof concludes the plugin does not work. It reproduces the state any
    // real project is in after its first turn.
    let fixture = std::env::temp_dir().join("vox-opencode-proof");
    let oc_cfg = fixture.join("config");
    let project = fixture.join("project");
    std::fs::create_dir_all(oc_cfg.join("opencode")).unwrap();
    std::fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
    // The credential is only *located* through the real data dir; nothing is copied.
    let _ = &auth;

    let env: Vec<(&str, &std::ffi::OsStr)> = vec![
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
    std::fs::write(
        project.join(".opencode/plugin/vox.js"),
        vox_tui::agent_hook::OPENCODE_PLUGIN,
    )
    .unwrap();
    for attempt in 0..3 {
        let _ = opencode_turn(&project, &env, false, "Reply with exactly: READY");
        if std::fs::read_to_string(&plugin_log)
            .map(|l| l.contains("chat.message"))
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            attempt < 2,
            "OpenCode never fired `chat.message` after three warm-up turns, so the plugin \
             seam could not be exercised at all.{}",
            plugin_diag("warm-up")
        );
    }
    let _ = std::fs::write(&plugin_log, "");

    // ---- the proof: a real model repeats something only the room told it ----
    let answer = opencode_turn(&project, &env, false, prompt);
    assert!(
        answer.contains(&codeword),
        "the room never reached the model. Expected {codeword:?} in the model's answer, got: \
         {answer:?}{}",
        plugin_diag("with plugin")
    );

    // ---- the mutation check: same everything, plugin disabled ----
    let without = opencode_turn(&project, &env, true, prompt);
    assert!(
        !without.contains(&codeword),
        "`--pure` disables external plugins, so the codeword must be unreachable — if it still \
         appears, this test is not measuring the plugin. Got: {without:?}"
    );
}
