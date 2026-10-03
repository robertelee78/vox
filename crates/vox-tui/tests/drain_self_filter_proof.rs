//! ADR-021 M21.6 — **a session's own messages are dropped from its drain only when
//! both the author and the session match**, through the shipped binary and a live
//! model.
//!
//! The drain hook used to inject every row after the cursor, including the session's
//! own posts (ADR-021 F8). The fix must not overreach, and each way of overreaching
//! silently loses a message meant for this agent:
//!
//! - matching on the **author** alone would drop every other session on this harness;
//! - matching on the **session name** alone would drop a *different harness* that
//!   happens to use the same name.
//!
//! **Deterministic half** — the real `vox agent hook`, as each harness runs it:
//!
//! - session `A` on harness H posts; session `B` on H posts; a session also named `A`
//!   on a **different harness** H′ posts;
//! - `A`'s drain on H shows B's message and H′'s `A` message, and not its own;
//! - `B`'s drain shows A's message, and not its own;
//! - H′'s `A` drain shows H's `A` message — same name, different author.
//!
//! **Live half**, **optional** (decider, 2026-10-01): its own test,
//! [`a_live_models_post_is_dropped_only_from_its_own_sessions_drain`], which runs only with
//! `--features optional-proofs` (docs/release/optional-proofs.md; without it a stand-in says it
//! was not run) — a real OpenCode turn, with
//! the plugin `vox agent plugin opencode`
//! prints: the model runs `vox room post` through its shell, and the plugin's
//! `shell.env` hook names the session. The proof reads the posted row back and
//! requires its `from` to be OpenCode's own session id — which is what makes the
//! filter (and per-session ownership) work for OpenCode at all — and then requires
//! that session's drain to omit that post while showing a message from H′.
//!
//! Each red of the live half names its side: the model never running the command is
//! APPARATUS (the model, not vox); `vox` refusing it is PRODUCT, quoting the refusal; and a
//! post `vox` accepted that never lands is PRODUCT.

#![cfg(unix)]

#[cfg(feature = "optional-proofs")]
#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;
#[path = "support/optional_proof.rs"]
mod optional_proof;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
// The optional half, loud when not run: see the header.
optional_proof::not_run!(a_live_models_post_is_dropped_only_from_its_own_sessions_drain);

#[cfg(feature = "optional-proofs")]
use std::{path::Path, process::Command};

#[cfg(feature = "optional-proofs")]
use support::VOX;
use support::{until, Out, Worker};

#[cfg(feature = "optional-proofs")]
fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

#[cfg(feature = "optional-proofs")]
fn model() -> String {
    oc_sandbox::model()
}

/// What `vox agent hook` injects for `session` on `w`, exactly as a harness runs it.
fn drain(w: &Worker, r: &str, session: &str) -> String {
    let o = w.vox_in(
        None,
        &["agent", "hook", "--room", r, "--format", "text"],
        Some(&format!(
            "{{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"{session}\"}}"
        )),
    );
    assert!(o.ok, "PRODUCT: a drain hook always exits 0: {o:?}");
    o.stdout
}

fn post(w: &Worker, r: &str, session: &str, body: &str) {
    let o = w.vox_in(
        Some(session),
        &["room", "post", r, "--type", "status", "-"],
        Some(body),
    );
    assert!(o.ok, "PRODUCT (staging): {o:?}");
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_drain_drops_only_its_own_session_on_its_own_harness() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: start a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["h", "h-prime"]));
    let (h, hp) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // ---- deterministic half ----
    post(h, r, "A", "OWN-A-ON-H");
    post(h, r, "B", "SIBLING-B-ON-H");
    post(hp, r, "A", "SAME-NAME-A-ON-H-PRIME");
    for w in [h, hp] {
        until(
            w,
            None,
            "all three posts everywhere",
            &["room", "read", r],
            |o: &Out| {
                ["OWN-A-ON-H", "SIBLING-B-ON-H", "SAME-NAME-A-ON-H-PRIME"]
                    .iter()
                    .all(|m| o.stdout.contains(m))
            },
        );
    }
    let a = drain(h, r, "A");
    assert!(
        !a.contains("OWN-A-ON-H"),
        "PRODUCT: A's drain re-injected A's own post: {a}"
    );
    assert!(
        a.contains("SIBLING-B-ON-H"),
        "PRODUCT: A's drain dropped another session of the same harness: {a}"
    );
    assert!(
        a.contains("SAME-NAME-A-ON-H-PRIME"),
        "PRODUCT: A's drain dropped a DIFFERENT harness that uses the same session name: {a}"
    );
    let b = drain(h, r, "B");
    assert!(
        !b.contains("SIBLING-B-ON-H") && b.contains("OWN-A-ON-H"),
        "PRODUCT: B's drain: {b}"
    );
    let ap = drain(hp, r, "A");
    assert!(
        !ap.contains("SAME-NAME-A-ON-H-PRIME") && ap.contains("OWN-A-ON-H"),
        "PRODUCT: H′'s A drain: {ap}"
    );
}

/// The **live half**: a real OpenCode session's own post, made by its model through the plugin,
/// is dropped from that session's drain and nothing else is. Optional: see the header.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two networked nodes with production Argon2id and live model turns; optional, run it in release"]
fn a_live_models_post_is_dropped_only_from_its_own_sessions_drain() {
    watchdog::arm();
    if !oc_sandbox::live_model_allowed(
        "drain_self_filter_proof::a_live_models_post_is_dropped_only_from_its_own_sessions_drain",
    ) {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: start a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["h", "h-prime"]));
    let (h, hp) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    assert!(
        which("opencode").is_some(),
        "APPARATUS (precondition not met): the live half needs `opencode` on PATH"
    );
    // **The model runs confined** (support/oc_sandbox.rs): a throwaway HOME, a fixed
    // environment, a whitelist of readable paths, a canary in the real HOME it must never see.
    // The plugin's hook and the model's `vox` need this run's two profiles; nothing else
    // outside the sandbox is readable. A missing credential is CANNOT MEASURE there.
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    let profile = sb.profile(
        "drain",
        &[&h.data, &h.cfg, &hp.data, &hp.cfg],
        &[Path::new(VOX)],
    );
    // **This run's own fixture, inside its sandbox**: OpenCode installs node_modules into a
    // project and its config directory on first use (the warm-up turn below), and a fixture
    // shared between runs let one tree's model run another tree's `vox` (2026-09-25).
    let fixture = sb.root.join("fixture");
    let project = fixture.join("project");
    let oc_cfg = fixture.join("config");
    std::fs::create_dir_all(project.join(".opencode/plugin"))
        .expect("APPARATUS: create a staging directory");
    std::fs::create_dir_all(oc_cfg.join("opencode"))
        .expect("APPARATUS: create a staging directory");
    std::fs::write(
        project.join(".opencode/plugin/vox.js"),
        vox_tui::agent_hook::OPENCODE_PLUGIN,
    )
    .expect("APPARATUS: write a staging file");
    let bin_dir = fixture.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("APPARATUS: create a staging directory");
    // **What the model's shell runs is recorded, with how `vox` answered it**, so a turn in
    // which the model never ran the operator's command (the apparatus) is told apart from one
    // in which Vox refused it (the product). The `vox` on the model's PATH is a recording
    // wrapper around the real binary; the plugin calls `VOX_BIN` directly, so only the model's
    // commands land here.
    let calls = fixture.join("model-shell-calls.log");
    let shim = bin_dir.join("vox");
    support::model_shim(&bin_dir, &calls);

    let turn = |prompt: &str| -> String {
        // Confined, with a fixed environment (`OcSandbox::opencode`): the recording `vox` shim
        // first on the model's PATH, then the system's.
        let mut cmd = sb.opencode(&profile, &[&bin_dir], &project);
        let out = cmd
            .args(["run", "--auto", "-m", &model(), prompt])
            .env("XDG_CONFIG_HOME", &oc_cfg)
            .env("VOX_DATA_DIR", &h.data)
            .env("VOX_CONFIG_DIR", &h.cfg)
            .env("VOX_ROOM", r)
            .env("VOX_BIN", VOX)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run opencode in its sandbox: {e}"));
        let s = format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        sb.check(&s, "an `opencode run` turn");
        eprintln!(
            "[receipt] opencode run --auto -m {} {prompt:?}\n{s}",
            model()
        );
        s
    };
    let _ = turn("Reply with exactly: READY"); // warm: the first turn in a fresh directory installs

    let codeword = format!("LIVE-SELF-{}", std::process::id());
    let _ = std::fs::write(&calls, "");
    let reply = turn(&format!(
        "Run exactly this shell command and nothing else, then reply DONE: \
         vox room post \"$VOX_ROOM\" --type status {codeword}"
    ));
    // **A model that does not run the command is the apparatus failing, not Vox.**
    // Measured 2026-09-26, opencode 1.18.32, a fixture per tree, 20 runs per arm: with
    // this drain framing, claude-haiku-4-5 and claude-sonnet-5 both ran the command 20/20.
    // With the old framing ("Reply with `vox room post …`" inside the block), sonnet-5
    // refused 5/20 as an instruction "embedded" in room content; haiku-4-5 0/20. Other real
    // misses seen: the command printed in a code block and not run, and a request for
    // `$VOX_ROOM`'s value. A shared fixture used to add false ones (two trees overwriting
    // each other's `vox`), which the per-tree fixture removed. Neither says anything about the drain, so
    // neither is reported as a product red — and neither is retried until green. It
    // fails as APPARATUS (the model, not vox), by name.
    // **Vox refusing the model's post is the product failing** (a plugin that names no
    // session gets "no session: … set VOX_SESSION"), and is a PRODUCT red quoting the refusal,
    // not a wait for a row that can never land.
    let ran = support::vox_accepted(&calls, "the model", "`vox room post`", |a| {
        a.contains("room post") && a.contains(&codeword)
    });
    if !ran {
        // Two different apparatus failures, told apart by the turn's own transcript
        // (OpenCode prints each shell command it runs as `$ <command>`):
        // - the model ran `vox room post <codeword>`, but not through the fixture's `vox`
        //   — a login shell that puts another `vox` first on PATH does this (causal-order
        //   found a 0.2.6 `~/.local/bin/vox`, which answers a newer node with "a control
        //   socket exists … but nothing answered");
        // - the model never ran it at all.
        let escaped = reply
            .lines()
            .any(|l| l.contains("$ ") && l.contains("vox room post") && l.contains(&codeword));
        let resolve = |args: &[&str]| -> String {
            let path = format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            Command::new(&shell)
                .args(args)
                .env_clear()
                .env("PATH", path)
                .env("HOME", std::env::var_os("HOME").unwrap_or_default())
                .env("SHELL", &shell)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default()
        };
        let what = if escaped {
            format!(
                "the model ran `vox room post`, but NOT through the fixture's `vox` ({}): its \
                 shell resolved another one — `command -v vox` gives {:?} in a plain shell and \
                 {:?} in a login shell",
                shim.display(),
                resolve(&["-c", "command -v vox"]),
                resolve(&["-lc", "command -v vox"]),
            )
        } else {
            "the model never ran the operator's `vox room post` in turn 2 — nothing reached \
             `vox`"
                .to_owned()
        };
        panic!(
            "APPARATUS (the model, not vox): model {}: {what}. Its reply:\n{reply}",
            model()
        );
    }
    let rows = support::arrives(
        h,
        "the model's post to land",
        &["room", "read", r, "--json"],
        |o: &Out| o.ok && o.stdout.contains(&codeword),
    )
    .ndjson();
    let mine = rows
        .iter()
        .find(|x| x["text"].as_str().is_some_and(|t| t.contains(&codeword)))
        .expect("PRODUCT: the session's own post is not in its room");
    let session = mine["envelope"]["from"].as_str().unwrap_or("").to_owned();
    assert!(
        session.starts_with("ses"),
        "PRODUCT: the model's post must carry OpenCode's own session id as `from` (the plugin's \
         shell.env names it), not {session:?}: {mine}"
    );

    post(hp, r, "A", "FROM-H-PRIME-AFTER");
    until(
        h,
        None,
        "H′'s later post to reach H",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("FROM-H-PRIME-AFTER"),
    );
    let d = drain(h, r, &session);
    assert!(
        !d.contains(&codeword),
        "PRODUCT: the session's drain re-injected the model's own post: {d}"
    );
    assert!(
        d.contains("FROM-H-PRIME-AFTER"),
        "PRODUCT: the session's drain dropped another harness's message: {d}"
    );
}
