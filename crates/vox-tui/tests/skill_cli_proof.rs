//! ADR-020 **M19.10** — **the agent skill and the CLI agree**, checked against the shipped
//! `vox` binary.
//!
//! The skill (`vox agent skill`) is what an agent reads to learn the CLI. A verb or flag it
//! names that the binary does not have costs an agent a failed command and a guess — and
//! nothing else notices, because the skill is prose. So this reads the skill **from the
//! binary**, exactly as an agent gets it, and asks the binary about every command in it:
//!
//! - every `vox …` command in a fenced block or an inline code span names a verb path the
//!   binary accepts — `vox <path> --help` succeeds — with `a|b|c` alternatives expanded;
//! - every `--flag` written with such a command appears in that command's `--help`;
//! - every flag the skill names on its own, as `` `--flag` ``, exists on at least one of
//!   the verbs the skill names.
//!
//! Prose that merely mentions the word `vox` is not a command and is not checked. The skill is
//! read as an agent gets it: the whole pack, as `vox agent skill --install` puts it in a scratch
//! `HOME`, every file of it.
//!
//! **The pack is installed for every harness, and an operator's edit is kept** (v0.4.1,
//! [`the_pack_is_installed_for_every_harness_here_and_an_edited_file_is_kept`]): `install.sh` and
//! `vox update` run `vox agent skill --install`, so that is what is driven, in a scratch `HOME`.
//! A fresh install puts the whole pack where each harness present reads it, and none for a harness
//! not here; a second run, as an update, refreshes a file an earlier Vox wrote and nobody changed,
//! and leaves a file the operator edited as it is, saying so. A `SKILL.md` from before the pack,
//! exactly as v0.3.1 shipped it (`fixtures/skill-from-v0.3.1.md`), is refreshed; one the operator
//! changed is kept. Mutants: the edit check dropped (an edited file overwritten) → red; the
//! shipped versions not recognised → red (v0.3.1's file kept).
//!
//! **Each real harness loads the pack, and its first turn carries the repo-room ask** (optional,
//! [`each_harness_loads_the_pack_and_is_asked_for_the_repos_room`]): the real Claude Code
//! (`claude -p`), Codex (`codex exec`) and OpenCode (`opencode run`) each run one turn against a
//! stand-in model on loopback (`support/model_standin.py`), which records what the harness sends
//! and answers "ok". No model runs and nothing leaves the machine: each harness is confined by
//! `oc_sandbox::offline_profile` (the live-model sandbox's file rules, a canary in the real HOME
//! probed first, and no network but the stand-in's port and the run's own Unix sockets), in a
//! scratch `HOME` holding only what `vox agent skill --install` and `vox agent plugin <harness>`
//! put there, with a made-up API key for the stand-in; nothing drives a login. Each turn starts in
//! a directory the room map does not name. The proof asserts, from what each harness sent its
//! model: the skill `vox-agent-comms` is listed by its name with the pack's description (so the
//! harness found the pack where `--install` put it, and accepted its front matter), and the
//! RB-5 ask arrived through `vox agent hook`, with the `vox room join <link> --node … --bind …`
//! command filled in. OpenCode is run without its Claude Code compatibility
//! (`OPENCODE_DISABLE_CLAUDE_CODE`), so Claude Code's copy of the pack cannot stand in for
//! OpenCode's own. Mutants, each red as PRODUCT: the pack's front-matter name changed (red at
//! Claude Code, the first harness run; OpenCode 1.18 does not refuse a name that differs from
//! its folder, it lists the skill under that name); the pack put elsewhere for Codex alone (red
//! at Codex) and for OpenCode alone (red at OpenCode); the ask not given (red at Claude Code).

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[cfg(feature = "optional-proofs")]
#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(each_harness_loads_the_pack_and_is_asked_for_the_repos_room);

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// Whether `help` lists `flag` as an option: only on option lines (those that begin,
/// after indentation, with `-`), and as a whole flag — `--to` is not satisfied by
/// `--to-session`, nor by prose that happens to mention it.
fn has_flag(help: &str, flag: &str) -> bool {
    help.lines()
        .filter(|l| l.trim_start().starts_with('-'))
        .any(|l| {
            l.match_indices(flag).any(|(i, _)| {
                let before_ok =
                    i == 0 || !l[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '-');
                let after_ok = !l[i + flag.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
                before_ok && after_ok
            })
        })
}

fn vox(args: &[&str]) -> (bool, String) {
    let out = Command::new(VOX)
        .args(args)
        .env_remove("VOX_ROOM")
        .env("VOX_DATA_DIR", "/nonexistent/vox-skill-proof")
        .env("VOX_CONFIG_DIR", "/nonexistent/vox-skill-proof")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// One command as the skill writes it: the verb path (alternatives expanded) and its flags.
#[derive(Debug)]
struct Cmd {
    paths: Vec<Vec<String>>,
    flags: BTreeSet<String>,
    source: String,
    section: usize,
}

fn is_verb(t: &str) -> bool {
    !t.is_empty()
        && t.split('|').all(|w| {
            w.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        })
}

fn parse_command(text: &str) -> Option<Cmd> {
    let at = text.find("vox ")?;
    let tokens: Vec<&str> = text[at + 4..].split_whitespace().collect();
    let mut verbs: Vec<Vec<String>> = vec![vec![]];
    let mut i = 0;
    while i < tokens.len() && is_verb(tokens[i]) {
        verbs = verbs
            .into_iter()
            .flat_map(|p| {
                tokens[i].split('|').map(move |w| {
                    let mut q = p.clone();
                    q.push(w.to_owned());
                    q
                })
            })
            .collect();
        i += 1;
    }
    if verbs[0].is_empty() {
        return None;
    }
    let flags = tokens[i..]
        .iter()
        .take_while(|t| !t.starts_with('#'))
        .filter(|t| t.starts_with("--") && t.len() > 2)
        .map(|t| {
            t.trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_owned()
        })
        .collect();
    Some(Cmd {
        paths: verbs,
        flags,
        source: text.trim().to_owned(),
        section: 0,
    })
}

/// Commands and bare flags, from fenced blocks (with `\` continuations joined) and inline
/// code spans. Each bare flag is kept with the section (`#` heading) it appears in, so it
/// can be checked against the verbs that section is about.
fn extract(skill: &str) -> (Vec<Cmd>, Vec<(String, usize)>) {
    let mut cmds = Vec::new();
    let mut bare = Vec::new();
    let mut section = 0usize;
    let mut fenced = false;
    let mut pending = String::new();
    for line in skill.lines() {
        // A section is a `#`/`##` heading; a `###` subsection belongs to its parent, so
        // a flag named under "What each type means" is checked against "Speaking"'s verbs.
        if !fenced && (line.starts_with("# ") || line.starts_with("## ")) {
            section += 1;
        }
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            pending.push_str(line.trim_end_matches('\\'));
            pending.push(' ');
            if line.trim_end().ends_with('\\') {
                continue;
            }
            if let Some(mut c) = parse_command(&pending) {
                c.section = section;
                cmds.push(c);
            }
            pending.clear();
            continue;
        }
        for (k, span) in line.split('`').enumerate() {
            if k % 2 == 0 {
                continue; // outside a code span
            }
            if span.starts_with("vox ") {
                if let Some(mut c) = parse_command(span) {
                    c.section = section;
                    cmds.push(c);
                }
            } else if let Some(flag) = span.split_whitespace().next().filter(|f| {
                f.starts_with("--")
                    && f.len() > 2
                    && f[2..].chars().all(|c| c.is_ascii_lowercase() || c == '-')
            }) {
                bare.push((flag.to_owned(), section));
            }
        }
    }
    (cmds, bare)
}

/// The files the pack is, by their path in its folder.
const PACK: &[&str] = &[
    "SKILL.md",
    "references/rooms.md",
    "references/sessions.md",
    "references/trust.md",
    "references/files.md",
    "references/setup.md",
];

/// `vox agent skill --install` with `home` as `HOME`, and only the harness folders `home` holds:
/// no harness program on `PATH`, no harness or Vox variable from this process's environment.
fn install(home: &std::path::Path) -> (bool, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(["agent", "skill", "--install"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("VOX_DATA_DIR", home.join("vox-data"))
        .env("VOX_CONFIG_DIR", home.join("vox-config"));
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent skill --install: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// Where `harness` reads the pack under `home`.
fn pack_in(home: &std::path::Path, harness: &str) -> std::path::PathBuf {
    let dir = match harness {
        "claude" => home.join(".claude"),
        "codex" => home.join(".codex"),
        _ => home.join(".config").join("opencode"),
    };
    dir.join("skills").join("vox-agent-comms")
}

#[test]
fn every_verb_and_flag_the_skill_names_exists_in_the_cli() {
    watchdog::arm();
    let home = tempfile::tempdir().expect("APPARATUS: a scratch HOME");
    std::fs::create_dir_all(home.path().join(".claude")).expect("APPARATUS: a harness folder");
    let (ok, said) = install(home.path());
    assert!(
        ok,
        "PRODUCT: vox agent skill --install must install the pack: {said}"
    );
    // The whole pack, each file a section of its own.
    let skill: String = PACK
        .iter()
        .map(|f| {
            std::fs::read_to_string(pack_in(home.path(), "claude").join(f)).unwrap_or_else(|e| {
                panic!("PRODUCT: the installed pack has no {f} ({e}); vox said:\n{said}")
            })
        })
        .collect::<Vec<_>>()
        .join("\n");
    // **What each harness loads** (Claude Code, Codex, OpenCode): a `SKILL.md` whose front matter
    // names the skill as its folder is named, and describes it on one line of at most 1024
    // characters; OpenCode refuses a skill whose name is not its folder's.
    let front = skill
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .map(|(f, _)| f)
        .unwrap_or_else(|| panic!("PRODUCT: the pack's SKILL.md has no front matter:\n{skill}"));
    let field = |k: &str| {
        front
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}: ")))
            .unwrap_or_default()
            .to_owned()
    };
    let (name, description) = (field("name"), field("description"));
    assert!(
        name == "vox-agent-comms"
            && !description.is_empty()
            && description.chars().count() <= 1024
            && front.lines().count() == 2,
        "PRODUCT: the pack's front matter must name it as its folder (vox-agent-comms) and \
         describe it on one line of at most 1024 characters: {front:?}"
    );
    let (cmds, bare) = extract(&skill);
    assert!(
        cmds.len() >= 10,
        "APPARATUS, CANNOT MEASURE: the extractor found {} of at least 10 commands in the skill, so this \
         gate would prove nothing: {cmds:?}\nthe skill:\n{skill}",
        cmds.len()
    );

    // Each verb path's `--help`: `Ok` with its text, or `Err` with what vox said instead, so a
    // red quotes the binary rather than only the skill.
    let mut help: BTreeMap<Vec<String>, Result<String, String>> = BTreeMap::new();
    let mut problems = Vec::new();
    for c in &cmds {
        for path in &c.paths {
            let h = help.entry(path.clone()).or_insert_with(|| {
                let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
                args.push("--help");
                let (ok, out) = vox(&args);
                if ok {
                    Ok(out)
                } else {
                    Err(out)
                }
            });
            let h = match h {
                Ok(h) => h,
                Err(said) => {
                    problems.push(format!(
                        "`vox {}` is not a command (from: {}); `vox {} --help` said: {}",
                        path.join(" "),
                        c.source,
                        path.join(" "),
                        said.trim()
                    ));
                    continue;
                }
            };
            for f in &c.flags {
                if !has_flag(h, f) {
                    problems.push(format!(
                        "`vox {}` has no {f} (from: {})",
                        path.join(" "),
                        c.source
                    ));
                }
            }
        }
    }
    // A bare flag belongs to the verbs of its own section; only a section that names no
    // command falls back to every verb the skill names.
    assert!(
        bare.len() >= 5,
        "APPARATUS, CANNOT MEASURE: the extractor found {} of at least 5 bare flags in the skill, so \
         this half would prove nothing: {bare:?}",
        bare.len()
    );
    for (f, section) in &bare {
        let local: Vec<&Vec<String>> = cmds
            .iter()
            .filter(|c| c.section == *section)
            .flat_map(|c| c.paths.iter())
            .collect();
        let found = if local.is_empty() {
            help.values().flatten().any(|h| has_flag(h, f))
        } else {
            local.iter().any(|p| {
                help.get(*p)
                    .is_some_and(|h| h.as_ref().is_ok_and(|h| has_flag(h, f)))
            })
        };
        if !found {
            problems.push(format!(
                "the skill names {f} in a section whose verbs ({local:?}) do not have it"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "PRODUCT: the skill that `vox agent skill` prints names commands the CLI does not have:\n  {}",
        problems.join("\n  ")
    );
    eprintln!(
        "[proof] checked {} commands ({} verb paths) and {} bare flags against the binary",
        cmds.len(),
        help.len(),
        bare.len()
    );
    for c in &cmds {
        eprintln!("[proof]   {:?} {:?}", c.paths, c.flags);
    }
    eprintln!("[proof]   bare: {bare:?}");
}

#[test]
fn the_pack_is_installed_for_every_harness_here_and_an_edited_file_is_kept() {
    watchdog::arm();
    let home = tempfile::tempdir().expect("APPARATUS: a scratch HOME");
    let home = home.path();
    // Claude Code and Codex are here (their settings folders); OpenCode is not.
    for d in [".claude", ".codex"] {
        std::fs::create_dir_all(home.join(d)).expect("APPARATUS: a harness folder");
    }

    // ---- a fresh install: the whole pack where each harness here reads it ----
    let (ok, said) = install(home);
    println!("[proof] fresh install:\n{said}");
    assert!(ok, "PRODUCT: vox agent skill --install failed: {said}");
    let (_, entry) = vox(&["agent", "skill"]);
    for h in ["claude", "codex"] {
        for f in PACK {
            let path = pack_in(home, h).join(f);
            assert!(
                path.is_file(),
                "PRODUCT: a fresh install must put {f} where {h} reads the pack ({}); vox said:\n{said}",
                path.display()
            );
        }
        let installed =
            std::fs::read_to_string(pack_in(home, h).join("SKILL.md")).unwrap_or_default();
        assert!(
            entry.starts_with(installed.trim_end()),
            "PRODUCT: the installed SKILL.md for {h} must be the entry `vox agent skill` prints"
        );
    }
    assert!(
        !pack_in(home, "opencode").exists() && said.contains("OpenCode: not found here"),
        "PRODUCT: no pack may be installed for OpenCode, which is not here, and the install must say \
         so; vox said:\n{said}"
    );

    // ---- an update over an earlier pack, untouched, and over a file the operator edited ----
    // What an earlier Vox wrote, as it recorded it: an older rooms.md, its hash in the manifest.
    let claude = pack_in(home, "claude");
    let older = "# Rooms (an earlier Vox's)\n";
    std::fs::write(claude.join("references/rooms.md"), older).expect("APPARATUS: an older file");
    let manifest_path = claude.join(".vox-pack.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .unwrap_or_else(|e| panic!("PRODUCT: the pack has no manifest ({e})")),
    )
    .expect("PRODUCT: the pack's manifest is JSON");
    manifest["files"]["references/rooms.md"] = {
        use sha2::{Digest as _, Sha256};
        let h: String = Sha256::digest(older.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        h.into()
    };
    std::fs::write(&manifest_path, manifest.to_string()).expect("APPARATUS: the manifest");
    // The operator's own line in Codex's entry.
    let codex_entry = pack_in(home, "codex").join("SKILL.md");
    let mut edited = std::fs::read_to_string(&codex_entry).unwrap_or_default();
    edited.push_str("\nOperator's note: always run the Linux suite too.\n");
    std::fs::write(&codex_entry, &edited).expect("APPARATUS: the operator's edit");

    let (ok, said) = install(home);
    println!("[proof] update:\n{said}");
    assert!(
        ok,
        "PRODUCT: a second vox agent skill --install failed: {said}"
    );
    let rooms = std::fs::read_to_string(claude.join("references/rooms.md")).unwrap_or_default();
    assert!(
        rooms != older && said.contains("refreshed") && said.contains("rooms.md"),
        "PRODUCT: an update must refresh a file an earlier Vox wrote and nobody changed, and say \
         so; rooms.md now holds {} bytes, and vox said:\n{said}",
        rooms.len()
    );
    let now = std::fs::read_to_string(&codex_entry).unwrap_or_default();
    assert!(
        now == edited,
        "PRODUCT: an update must leave a file the operator edited as it is; Codex's SKILL.md lost \
         the operator's note (vox said:\n{said})"
    );
    assert!(
        said.contains(&format!("left {} as it is", codex_entry.display())),
        "PRODUCT: an update that keeps the operator's file must say so, naming it; vox said:\n{said}"
    );
    // A third run changes nothing more, and still keeps the edit.
    let (ok, said) = install(home);
    assert!(
        ok && std::fs::read_to_string(&codex_entry).unwrap_or_default() == edited
            && said.contains("as it is"),
        "PRODUCT: the install must be idempotent, still keeping the edit; vox said:\n{said}"
    );
    println!("[proof] third run:\n{said}");

    // ---- a SKILL.md from before the pack: as v0.3.1 shipped it, and as an operator changed it ----
    let earlier = include_str!("fixtures/skill-from-v0.3.1.md");
    let before = tempfile::tempdir().expect("APPARATUS: a scratch HOME");
    let before = before.path();
    for (h, text) in [
        ("claude", earlier.to_owned()),
        (
            "codex",
            format!("{earlier}\nOperator's own rule: no force pushes.\n"),
        ),
    ] {
        let dir = pack_in(before, h);
        std::fs::create_dir_all(&dir).expect("APPARATUS: an earlier skill's folder");
        std::fs::write(dir.join("SKILL.md"), text).expect("APPARATUS: an earlier skill");
    }
    let (ok, said) = install(before);
    println!("[proof] install over a SKILL.md from before the pack:\n{said}");
    let (_, entry) = vox(&["agent", "skill"]);
    let claude_now =
        std::fs::read_to_string(pack_in(before, "claude").join("SKILL.md")).unwrap_or_default();
    assert!(
        ok && entry.starts_with(claude_now.trim_end())
            && said.contains(&format!("refreshed {}", pack_in(before, "claude").join("SKILL.md").display())),
        "PRODUCT: a SKILL.md exactly as v0.3.1 shipped it must be refreshed to this version's, and \
         the install must say so; vox said:\n{said}"
    );
    let codex_now =
        std::fs::read_to_string(pack_in(before, "codex").join("SKILL.md")).unwrap_or_default();
    assert!(
        codex_now.contains("Operator's own rule: no force pushes.")
            && said.contains(&format!(
                "left {} as it is",
                pack_in(before, "codex").join("SKILL.md").display()
            )),
        "PRODUCT: a SKILL.md from before the pack that the operator changed must be kept, and the \
         install must say so; vox said:\n{said}"
    );
}

/// Every string in `v`, joined by newlines: what a harness sent its model, as text, whatever the
/// API's shape (Anthropic Messages, OpenAI Responses or Chat Completions).
#[cfg(feature = "optional-proofs")]
fn strings_of(v: &serde_json::Value, out: &mut String) {
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

/// Children this proof started (the daemon, the stand-in model), stopped however it ends.
#[cfg(feature = "optional-proofs")]
struct Stop(Vec<std::process::Child>);

#[cfg(feature = "optional-proofs")]
impl Drop for Stop {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// See the module doc: each real harness, confined and offline against a stand-in model, lists
/// the installed pack and is given the RB-5 ask on its first turn in an unmapped directory.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: starts Claude Code, Codex and OpenCode against a stand-in model on loopback"]
fn each_harness_loads_the_pack_and_is_asked_for_the_repos_room() {
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    watchdog::arm_for(Duration::from_secs(900));
    if !cfg!(target_os = "macos") {
        panic!(
            "CANNOT MEASURE: the harnesses are confined with macOS sandbox-exec, so this proof \
             runs on macOS only"
        );
    }
    const ASK: &str =
        "This repo isn't tied to a Vox room. Paste its room link to bind it, or say no.";

    // ---- the three harnesses, as installed here; the sandbox reads each one's install ----
    let find = |bin: &str| -> PathBuf {
        let on_path = std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(bin))
                .find(|p| p.is_file())
        });
        oc_sandbox::real(&on_path.unwrap_or_else(|| {
            panic!("CANNOT MEASURE: {bin} is not on PATH, so it cannot be started")
        }))
    };
    let (claude, codex, opencode) = (find("claude"), find("codex"), find("opencode"));
    let install_of = |bin: &Path| -> PathBuf {
        let dir = bin
            .parent()
            .expect("APPARATUS: a harness binary has a directory");
        // Codex's standalone install keeps its binary in `<release>/bin`, beside its resources.
        if dir.file_name().is_some_and(|n| n == "bin") && bin.ends_with("codex") {
            dir.parent().unwrap_or(dir).to_path_buf()
        } else {
            dir.to_path_buf()
        }
    };
    let installs = [
        install_of(&claude),
        install_of(&codex),
        install_of(&opencode),
    ];

    // ---- the run's root: a scratch HOME with each harness's folder, the repo, the profile ----
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = oc_sandbox::real(tmp.path());
    let (home, data, cfg, t, repo, bin) = (
        root.join("home"),
        root.join("data"),
        root.join("cfg"),
        root.join("t"),
        root.join("repo"),
        root.join("bin"),
    );
    for d in [
        home.join(".claude"),
        home.join(".codex"),
        home.join(".config/opencode/plugin"),
        cfg.clone(),
        t.clone(),
        repo.clone(),
        bin.clone(),
        root.join("xdg/data"),
        root.join("xdg/state"),
        root.join("xdg/cache"),
    ] {
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    // The daemon's control socket lives under TMPDIR, and a Unix socket's path holds 104 bytes.
    let socket = t.join("vox-50100/0123456789abcdef.new");
    assert!(
        socket.as_os_str().len() < 104,
        "APPARATUS: the run's root {} is too long for the daemon's control socket under it; set \
         TMPDIR to a shorter directory",
        root.display()
    );
    // The hooks run `vox` by name: this build, in the run's own bin.
    let vox_bin = bin.join("vox");
    std::fs::copy(VOX, &vox_bin).expect("APPARATUS: cannot copy vox into the run's bin");
    let path = format!("{}:{}", bin.display(), oc_sandbox::SANDBOX_PATH);
    let env = |c: &mut Command| {
        c.env_clear()
            .env("PATH", &path)
            .env("HOME", &home)
            .env("TMPDIR", &t)
            .env("VOX_DATA_DIR", &data)
            .env("VOX_CONFIG_DIR", &cfg)
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("LANG", "en_US.UTF-8");
    };
    let vox = |args: &[&str]| -> (bool, String, String) {
        let mut c = Command::new(&vox_bin);
        env(&mut c);
        let out = c
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox {args:?}: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // ---- (1) the agent's node (`default`) and its daemon ----
    let pass = root.join("identity.pass");
    std::fs::write(&pass, "identity passphrase").expect("APPARATUS: the passphrase file");
    let pass_arg = pass.to_str().expect("APPARATUS: a UTF-8 path");
    let (ok, _, err) = vox(&["id", "--identity-passphrase-file", pass_arg]);
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");
    let daemon_err = root.join("daemon.err");
    let mut c = Command::new(&vox_bin);
    env(&mut c);
    let daemon = c
        .args([
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            pass_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&daemon_err).expect("APPARATUS: the daemon's stderr file"),
        ))
        .spawn()
        .expect("APPARATUS: cannot start vox daemon");
    let mut stop = Stop(vec![daemon]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(&["room", "list"]).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never answered `vox room list` in 60 s; it said:\n{}",
            std::fs::read_to_string(&daemon_err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // ---- (2) the pack, as install.sh and `vox update` install it, and each harness's wiring ----
    let (ok, out, err) = vox(&["agent", "skill", "--install"]);
    println!("[proof] vox agent skill --install:\n{out}{err}");
    assert!(ok, "PRODUCT: vox agent skill --install failed: {out}{err}");
    let entry = std::fs::read_to_string(pack_in(&home, "claude").join("SKILL.md"))
        .unwrap_or_else(|e| panic!("PRODUCT: the pack has no SKILL.md for Claude Code ({e})"));
    let description: String = entry
        .lines()
        .find_map(|l| l.strip_prefix("description: "))
        .unwrap_or_else(|| panic!("PRODUCT: the pack's SKILL.md has no description line"))
        .chars()
        .take(60)
        .collect();
    let plugin = |harness: &str, to: &Path| {
        let (ok, out, err) = vox(&["agent", "plugin", harness, "--node", "default"]);
        assert!(
            ok,
            "PRODUCT: `vox agent plugin {harness} --node default` failed: {err}"
        );
        std::fs::write(to, out).unwrap_or_else(|e| panic!("APPARATUS: cannot write {to:?}: {e}"));
    };
    plugin("claude", &home.join(".claude/settings.json"));
    plugin("codex", &home.join(".codex/hooks.json"));
    plugin("opencode", &home.join(".config/opencode/plugin/vox.js"));

    // ---- (3) the stand-in model, and the profile every harness runs under ----
    let port_file = root.join("model.port");
    let log = root.join("model.jsonl");
    let model = Command::new("/usr/bin/python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/model_standin.py"
        ))
        .arg(&port_file)
        .arg(&log)
        .env_clear()
        .env("PATH", oc_sandbox::SANDBOX_PATH)
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start the stand-in model: {e}"));
    stop.0.push(model);
    let deadline = Instant::now() + Duration::from_secs(20);
    let port: u16 = loop {
        if let Some(p) = std::fs::read_to_string(&port_file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            break p;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: the stand-in model did not listen within 20 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let url = format!("http://127.0.0.1:{port}");
    std::fs::write(
        home.join(".codex/config.toml"),
        format!(
            "model = \"stub-model\"\nmodel_provider = \"standin\"\n\n[model_providers.standin]\n\
             name = \"standin\"\nbase_url = \"{url}/v1\"\nwire_api = \"responses\"\n\
             env_key = \"STANDIN_API_KEY\"\n"
        ),
    )
    .expect("APPARATUS: Codex's config.toml");
    std::fs::write(
        home.join(".config/opencode/opencode.json"),
        serde_json::json!({
            "autoupdate": false,
            "share": "disabled",
            "provider": { "standin": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "standin",
                "options": { "baseURL": format!("{url}/v1"), "apiKey": "made-up-key-for-a-stand-in" },
                "models": { "stub-model": { "name": "stub-model" } }
            }},
            "model": "standin/stub-model"
        })
        .to_string(),
    )
    .expect("APPARATUS: OpenCode's opencode.json");
    let canary = oc_sandbox::Canary::plant();
    let readable: Vec<&Path> = installs.iter().map(PathBuf::as_path).collect();
    let profile = root.join("harness.sb");
    std::fs::write(
        &profile,
        oc_sandbox::offline_profile(&[&root], &readable, port),
    )
    .expect("APPARATUS: the sandbox profile");
    oc_sandbox::probe_profile(&profile, &canary, "harnesses on the stand-in model");

    // ---- (4) one turn in each harness, in the repo the room map does not name ----
    let sent = || std::fs::read_to_string(&log).unwrap_or_default();
    let turn =
        |name: &str, program: &Path, args: &[&str], extra: &[(&str, &str)]| -> String {
            let before = sent().lines().count();
            let mut c = Command::new("/usr/bin/sandbox-exec");
            env(&mut c);
            c.envs(extra.iter().copied())
                .arg("-f")
                .arg(&profile)
                .arg(program)
                .args(args)
                .current_dir(&repo)
                .stdin(Stdio::null());
            let started = Instant::now();
            let out = c
                .output()
                .unwrap_or_else(|e| panic!("APPARATUS: cannot start {name}: {e}"));
            let said = format!(
                "{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let lines: Vec<String> = sent().lines().skip(before).map(str::to_owned).collect();
            let mut text = String::new();
            for l in &lines {
                let v: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!("APPARATUS: the stand-in's log is not JSON lines: {e}")
                });
                strings_of(&v["body"], &mut text);
            }
            canary.check(&said, &format!("{name}'s output"));
            canary.check(&text, &format!("what {name} sent its model"));
            std::fs::write(root.join(format!("{name}.out")), &said)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot keep {name}'s output: {e}"));
            println!(
                "[proof] {name}: exit {:?} after {:.1}s; {} requests to the stand-in model",
                out.status.code(),
                started.elapsed().as_secs_f64(),
                lines.len()
            );
            assert!(
            out.status.success() && !lines.is_empty(),
            "APPARATUS: {name} did not finish a turn against the stand-in model (exit {:?}, {} \
             requests); it said:\n{}",
            out.status.code(),
            lines.len(),
            said.chars().rev().take(3000).collect::<String>().chars().rev().collect::<String>()
        );
            text
        };
    let bind = format!(
        "vox room join <link> --node default --bind {}",
        repo.display()
    );
    let vox_lines = |text: &str| -> String {
        text.lines()
            .filter(|l| l.to_ascii_lowercase().contains("vox"))
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let check = |name: &str, text: &str, listed: &[String]| {
        assert!(
            listed.iter().all(|l| text.contains(l.as_str())),
            "PRODUCT: {name} did not load the installed pack: what it sent its model lists no skill \
             `vox-agent-comms` with the pack's description (looked for {listed:?}); the lines \
             naming vox were:\n{}",
            vox_lines(text)
        );
        assert!(
            text.contains(ASK) && text.contains(&bind),
            "PRODUCT: {name}'s first turn in a directory the room map does not name was not given \
             the RB-5 ask through `vox agent hook` (\"{ASK}\", with `{bind}`); the lines naming \
             vox were:\n{}",
            vox_lines(text)
        );
        println!(
            "[proof] {name}: lists `vox-agent-comms` and was given the RB-5 ask with `{bind}`"
        );
    };
    let skill_line = format!("- vox-agent-comms: {description}");

    let sent_claude = turn(
        "Claude Code",
        &claude,
        &["-p", "--model", "claude-sonnet-4-5", "hello"],
        &[
            ("ANTHROPIC_BASE_URL", url.as_str()),
            ("ANTHROPIC_API_KEY", "made-up-key-for-a-stand-in"),
            (
                "CLAUDE_CODE_TMPDIR",
                t.to_str().expect("APPARATUS: a UTF-8 path"),
            ),
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
            ("DISABLE_AUTOUPDATER", "1"),
        ],
    );
    check(
        "Claude Code",
        &sent_claude,
        std::slice::from_ref(&skill_line),
    );

    let codex_home = home.join(".codex");
    let codex_env = [
        (
            "CODEX_HOME",
            codex_home.to_str().expect("APPARATUS: a UTF-8 path"),
        ),
        ("STANDIN_API_KEY", "made-up-key-for-a-stand-in"),
    ];
    // Codex runs a hook only once it is trusted; `vox agent trust codex` is how an operator
    // trusts Vox's, through Codex's own app-server, in the same sandbox.
    let mut c = Command::new("/usr/bin/sandbox-exec");
    env(&mut c);
    let trusted = c
        .envs(codex_env)
        .arg("-f")
        .arg(&profile)
        .arg(&vox_bin)
        .args(["agent", "trust", "codex", "--codex"])
        .arg(&codex)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent trust codex: {e}"));
    assert!(
        trusted.status.success(),
        "PRODUCT (staging): `vox agent trust codex` failed: {}{}",
        String::from_utf8_lossy(&trusted.stdout),
        String::from_utf8_lossy(&trusted.stderr)
    );
    let sent_codex = turn(
        "Codex",
        &codex,
        &["exec", "--skip-git-repo-check", "hello"],
        &codex_env,
    );
    check("Codex", &sent_codex, std::slice::from_ref(&skill_line));

    let xdg = |d: &str| root.join("xdg").join(d).display().to_string();
    let config = home.join(".config").display().to_string();
    let sent_opencode = turn(
        "OpenCode",
        &opencode,
        &["run", "--model", "standin/stub-model", "hello"],
        &[
            ("XDG_CONFIG_HOME", config.as_str()),
            ("XDG_DATA_HOME", xdg("data").as_str()),
            ("XDG_STATE_HOME", xdg("state").as_str()),
            ("XDG_CACHE_HOME", xdg("cache").as_str()),
            ("OPENCODE_DISABLE_MODELS_FETCH", "1"),
            ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
            ("OPENCODE_DISABLE_LSP_DOWNLOAD", "1"),
            // Its Claude Code compatibility would read ~/.claude/skills, where Claude Code's
            // copy of the pack could stand in for OpenCode's own.
            ("OPENCODE_DISABLE_CLAUDE_CODE", "1"),
        ],
    );
    check(
        "OpenCode",
        &sent_opencode,
        &[
            "<name>vox-agent-comms</name>".to_owned(),
            format!("<description>{description}"),
        ],
    );
    drop(stop);
}
