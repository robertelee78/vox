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
//! **Live half** — a real OpenCode turn, with the plugin `vox agent plugin opencode`
//! prints: the model runs `vox room post` through its shell, and the plugin's
//! `shell.env` hook names the session. The proof reads the posted row back and
//! requires its `from` to be OpenCode's own session id — which is what makes the
//! filter (and per-session ownership) work for OpenCode at all — and then requires
//! that session's drain to omit that post while showing a message from H′.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::Command;

use support::{until, Out, Worker, VOX};

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

/// What `vox agent hook` injects for `session` on `w`, exactly as a harness runs it.
fn drain(w: &Worker, r: &str, session: &str) -> String {
    let o = w.vox_in(
        None,
        &["agent", "hook", "--room", r, "--format", "text"],
        Some(&format!(
            "{{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"{session}\"}}"
        )),
    );
    assert!(o.ok, "a drain hook always exits 0: {o:?}");
    o.stdout
}

fn post(w: &Worker, r: &str, session: &str, body: &str) {
    let o = w.vox_in(
        Some(session),
        &["room", "post", r, "--type", "status", "-"],
        Some(body),
    );
    assert!(o.ok, "{o:?}");
}

#[test]
#[ignore = "two networked nodes with production Argon2id and a live model turn; CI runs it in release"]
fn a_drain_drops_only_its_own_session_on_its_own_harness() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
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
        "A's drain re-injected A's own post: {a}"
    );
    assert!(
        a.contains("SIBLING-B-ON-H"),
        "A's drain dropped another session of the same harness: {a}"
    );
    assert!(
        a.contains("SAME-NAME-A-ON-H-PRIME"),
        "A's drain dropped a DIFFERENT harness that uses the same session name: {a}"
    );
    let b = drain(h, r, "B");
    assert!(
        !b.contains("SIBLING-B-ON-H") && b.contains("OWN-A-ON-H"),
        "B's drain: {b}"
    );
    let ap = drain(hp, r, "A");
    assert!(
        !ap.contains("SAME-NAME-A-ON-H-PRIME") && ap.contains("OWN-A-ON-H"),
        "H′'s A drain: {ap}"
    );

    // ---- live half ----
    if which("opencode").is_none() || !auth_present() {
        assert!(
            allow_unproven("opencode"),
            "UNPROVEN: the live half needs `opencode` and a credential. Set \
             VOX_PROOF_ALLOW_UNPROVEN=opencode to accept that gap deliberately."
        );
        return;
    }
    // A persistent fixture: OpenCode installs node_modules into a project and its config
    // directory on first use, and until then a plugin may load while its hooks never fire.
    //
    // **One fixture per `vox` under test, never one for the machine.** It was a single fixed
    // path, and every run rewrites its `bin/vox` and its plugin. Two trees proving at once
    // (v0.2.9 and v0.3.0 did, 2026-09-25) each replaced the other's: one tree's model ran
    // the *other* tree's `vox` against its own node and got "a control socket exists … but
    // nothing answered", which read as a Vox failure in one tree and as a model miss in the
    // other. Keyed by the binary's path, a tree still reuses its own OpenCode install.
    let fixture = std::env::temp_dir().join(format!("vox-drain-self-filter-{:016x}", {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        VOX.hash(&mut h);
        h.finish()
    }));
    let project = fixture.join("project");
    let oc_cfg = fixture.join("config");
    std::fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
    std::fs::create_dir_all(oc_cfg.join("opencode")).unwrap();
    std::fs::write(
        project.join(".opencode/plugin/vox.js"),
        vox_tui::agent_hook::OPENCODE_PLUGIN,
    )
    .unwrap();
    let bin_dir = fixture.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    // **What the model's shell runs is recorded**, so a turn in which the model never
    // ran the operator's command is told apart from one in which Vox failed it. The
    // `vox` on the model's PATH is a wrapper that logs its arguments and runs the real
    // binary; the plugin calls `VOX_BIN` directly, so only the model's commands land here.
    let calls = fixture.join("model-shell-calls.log");
    let shim = bin_dir.join("vox");
    let _ = std::fs::remove_file(&shim);
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            calls.display(),
            VOX
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let turn = |prompt: &str| -> String {
        let mut cmd = Command::new("opencode");
        // A spawned OpenCode that inherits cargo's environment never fires its plugin
        // hooks (measured, ADR-020 M19.5b): clear it and pass only what is needed.
        cmd.env_clear();
        for key in ["HOME", "SHELL", "LANG", "TMPDIR", "USER"] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = cmd
            .current_dir(&project)
            .args(["run", "--auto", "-m", &model(), prompt])
            .env("PATH", path)
            .env("XDG_CONFIG_HOME", &oc_cfg)
            .env("VOX_DATA_DIR", &h.data)
            .env("VOX_CONFIG_DIR", &h.cfg)
            .env("VOX_ROOM", r)
            .env("VOX_BIN", VOX)
            .output()
            .expect("run opencode");
        let s = format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
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
    // Measured 2026-09-25, opencode 1.18.32, with a fixture per tree: claude-haiku-4-5
    // 20/20 and claude-sonnet-5 20/20 ran the command, 0 misses. Earlier "misses" were
    // mostly the shared fixture (two trees overwriting each other's `vox`). Real ones seen
    // before that: a refusal as "embedded in messages" (vox-bc, v0.3.0), the command
    // printed in a code block and not run, and a request for `$VOX_ROOM`'s value. Neither says anything about the drain, so
    // neither is reported as a product red — and neither is retried until green. It
    // fails as CANNOT PROVE, by name, unless that gap is accepted deliberately.
    let ran = std::fs::read_to_string(&calls)
        .unwrap_or_default()
        .lines()
        .any(|l| l.contains("room post") && l.contains(&codeword));
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
        assert!(
            allow_unproven("opencode-model-miss"),
            "CANNOT PROVE (apparatus, not product): model {}: {what}. Its reply:\n{reply}\n\
             Set VOX_PROOF_ALLOW_UNPROVEN=opencode-model-miss to accept that gap deliberately.",
            model()
        );
        eprintln!("[unproven] {what}; the live half proves nothing");
        return;
    }
    let rows = until(
        h,
        None,
        "the model's post to land",
        &["room", "read", r, "--json"],
        |o: &Out| o.ok && o.stdout.contains(&codeword),
    )
    .ndjson();
    let mine = rows
        .iter()
        .find(|x| x["text"].as_str().is_some_and(|t| t.contains(&codeword)))
        .unwrap();
    let session = mine["envelope"]["from"].as_str().unwrap_or("").to_owned();
    assert!(
        session.starts_with("ses"),
        "the model's post must carry OpenCode's own session id as `from` (the plugin's \
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
        "the session's drain re-injected the model's own post: {d}"
    );
    assert!(
        d.contains("FROM-H-PRIME-AFTER"),
        "the session's drain dropped another harness's message: {d}"
    );
}
