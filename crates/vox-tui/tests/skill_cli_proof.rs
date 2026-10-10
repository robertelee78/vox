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
//!
//! **At the start of a session, each harness finds its node, then its room, from the skill
//! alone** (#666, the same optional proof): no harness is wired to Vox at first, so there is no
//! hook, only the pack. The stand-in plays a model doing what the pack's description says
//! (`model_standin.py --run-status`): it runs `vox agent status --harness <harness>` through the
//! harness's own shell tool, and repeats what it printed. Each harness's first session prints
//! that it has no node and the `vox agent connect <harness> --node <name>` command. The
//! operator's command is then run, with the passphrase from a file (`--passphrase-file`): it
//! makes the node, wires the hook, attaches the node. The next session is given the RB-5 ask by
//! the hook (above), and prints the status saying the node is attached and the repo is tied to
//! no room, with the `vox room join <link> --node <node> --bind <repo>` command. Mutants, each
//! red as PRODUCT at Claude Code: `vox agent status` reporting nothing missing for a harness with
//! no node; it leaving out the room ask; the pack's description without the status instruction
//! (the stand-in, like a model reading it, then runs nothing).
//!
//! **Each harness runs the pack's commands as the pack writes them, read and drive trust
//! included** (#662, the same optional proof). The operator's part is run as the pack gives it to
//! them: a person's node `alice` makes a room; Claude Code's node joins it with `vox room join
//! <link> --node … --bind <repo>`, the other two without `--bind`; each pair of nodes trusts the
//! other to read, typed at a terminal (`support/typed.rs`); Claude Code's node trusts alice with
//! `vox trust add … --drive`, and OpenCode's node gives Codex's drive with `vox trust drive`. Then
//! the stand-in plays an agent following the pack (`model_standin.py --script`): each command is
//! one call of the harness's own shell tool, and what the harness gave back is what is asserted.
//! OpenCode's session holds its last command until the other two are done, so its Session is open
//! while Codex's (with drive) and Claude Code's (read only) reach it. Asserted, as PRODUCT:
//! Claude Code and OpenCode name no node (`VOX_NODE`) with four nodes attached, Codex names it on
//! every command but `vox agent status`; `vox trust list` says `read` or `read + drive` per
//! entry; posts (plain, `--re`, typed from stdin, `--type ask|blocked`, `--urgent`), and a post
//! to another node says what to expect of it; claims (twice with one `--op`), board, renew,
//! release, handoff and decline; `vox room sessions --json` says `"can_drive":true` to Codex and
//! `false` to Claude Code for OpenCode's open Session; Codex reads inside it, and its `--say` and
//! `--file` are taken; Claude Code is told "Only members opencode-proof trusts with drive see
//! inside this Session." and its `--say` is refused "does not trust you with drive"; a keyring
//! change's passphrase from a file is refused; share, share list and stop, ping, `vox agent
//! send`, `vox agent doctor`, `vox agent room`; Claude Code's turn carries alice's message. `vox
//! room get` reaches its daemon's forward on an ephemeral loopback port, which the sandbox keeps
//! closed, so it runs outside the harness, as Claude Code's node in the repo. Mutants, each red
//! as PRODUCT: every Session's `can_drive` said false (red at Codex's `--json`); the Session view
//! shown to a member without drive (red at Claude Code's "Only members").

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[cfg(feature = "optional-proofs")]
#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[cfg(feature = "optional-proofs")]
#[path = "support/typed.rs"]
mod typed;

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

/// Writes its file when dropped: what lets a harness's waiting command go.
#[cfg(feature = "optional-proofs")]
struct Release(std::path::PathBuf);

#[cfg(feature = "optional-proofs")]
impl Drop for Release {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.0, "");
    }
}

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

    watchdog::arm_for(Duration::from_secs(3600));
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

    // ---- (1) the account's daemon, with no node: no harness is wired to Vox yet ----
    let pass = root.join("identity.pass");
    std::fs::write(&pass, "identity passphrase").expect("APPARATUS: the passphrase file");
    let pass_arg = pass.to_str().expect("APPARATUS: a UTF-8 path");
    let daemon_err = root.join("daemon.err");
    let mut c = Command::new(&vox_bin);
    env(&mut c);
    let daemon_log = std::fs::File::create(&daemon_err).expect("APPARATUS: the daemon's log file");
    let daemon = c
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            daemon_log
                .try_clone()
                .expect("APPARATUS: the daemon's log file"),
        ))
        .stderr(Stdio::from(daemon_log))
        .spawn()
        .expect("APPARATUS: cannot start vox daemon");
    let mut stop = Stop(vec![daemon]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::fs::read_to_string(&daemon_err)
        .unwrap_or_default()
        .contains("control socket")
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never said it listens on its control socket in 60 s; \
             it said:\n{}",
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
    // What the operator runs when the session says so: the node made, the harness wired to it,
    // the node attached. The passphrase comes from a file here; at a terminal it is typed.
    let connect = |harness: &str, node: &str| {
        let (ok, out, err) = vox(&[
            "agent",
            "connect",
            harness,
            "--node",
            node,
            "--passphrase-file",
            pass_arg,
        ]);
        println!("[proof] vox agent connect {harness} --node {node}:\n{out}{err}");
        assert!(
            ok,
            "PRODUCT: `vox agent connect {harness} --node {node}` failed: {out}{err}"
        );
    };

    // ---- (3) the stand-in model, and the profile every harness runs under ----
    let port_file = root.join("model.port");
    let log = root.join("model.jsonl");
    let script_dir = root.join("script");
    std::fs::create_dir_all(&script_dir).expect("APPARATUS: the stand-in's script directory");
    let model = Command::new("/usr/bin/python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/model_standin.py"
        ))
        .arg(&port_file)
        .arg(&log)
        .arg("--run-status")
        .arg("--script")
        .arg(&script_dir)
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
            "model": "standin/stub-model",
            "permission": { "bash": "allow" }
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
        |name: &str, program: &Path, args: &[&str], extra: &[(&str, &str)]| -> (String, String) {
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
            // This harness's requests alone: another harness may be in a turn at the same time.
            let endpoint = match name {
                "Claude Code" => "\"path\": \"/v1/messages",
                "Codex" => "\"path\": \"/v1/responses",
                _ => "\"path\": \"/v1/chat/completions",
            };
            let lines: Vec<String> = sent()
                .lines()
                .skip(before)
                .filter(|l| l.contains(endpoint))
                .map(str::to_owned)
                .collect();
            let mut text = String::new();
            for l in &lines {
                let v: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!("APPARATUS: the stand-in's log is not JSON lines: {e}")
                });
                strings_of(&v["body"], &mut text);
            }
            canary.check(&said, &format!("{name}'s output"));
            canary.check(&text, &format!("what {name} sent its model"));
            std::fs::write(root.join(format!("{name}-{before}.out")), &said)
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
            (text, said)
        };
    let bind = |node: &str| {
        format!(
            "vox room join <link> --node {node} --bind {}",
            repo.display()
        )
    };
    let vox_lines = |text: &str| -> String {
        text.lines()
            .filter(|l| l.to_ascii_lowercase().contains("vox"))
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let loaded = |name: &str, text: &str, listed: &[String]| {
        assert!(
            listed.iter().all(|l| text.contains(l.as_str())),
            "PRODUCT: {name} did not load the installed pack: what it sent its model lists no skill \
             `vox-agent-comms` with the pack's description (looked for {listed:?}); the lines \
             naming vox were:\n{}",
            vox_lines(text)
        );
    };
    // A session with no node: the status it ran, repeated, says so and names the command.
    let no_node = |name: &str, key: &str, said: &str| {
        let want = [
            "VOX STATUS SAID:".to_owned(),
            format!("{name} has no node on this machine"),
            format!("vox agent connect {key} --node {key}-"),
        ];
        assert!(
            want.iter().all(|w| said.contains(w.as_str())),
            "PRODUCT: {name}'s first session, with no node, did not say so from the skill alone: \
             `vox agent status --harness {key}`, run as the pack says, was to print {want:?}; the \
             session printed:\n{said}"
        );
        println!("[proof] {name}: with no node, the session said so and named `vox agent connect`");
    };
    // A session with its node attached and no room: the hook's ask, and the status's.
    let no_room = |name: &str, node: &str, text: &str, said: &str| {
        let bind = bind(node);
        assert!(
            text.contains(ASK) && text.contains(&bind),
            "PRODUCT: {name}'s first turn in a directory the room map does not name was not given \
             the RB-5 ask through `vox agent hook` (\"{ASK}\", with `{bind}`); the lines naming \
             vox were:\n{}",
            vox_lines(text)
        );
        let want = [
            "VOX STATUS SAID:".to_owned(),
            format!("{name} is node {node}, attached."),
            ASK.to_owned(),
            bind.clone(),
        ];
        assert!(
            want.iter().all(|w| said.contains(w.as_str())),
            "PRODUCT: {name}'s session with node {node} attached and no room did not say so: \
             `vox agent status`, run as the pack says, was to print {want:?}; the session \
             printed:\n{said}"
        );
        println!(
            "[proof] {name}: lists `vox-agent-comms`, and was given the RB-5 ask with `{bind}` by \
             the hook and by the status"
        );
    };
    let skill_line = format!("- vox-agent-comms: {description}");

    let claude_args = [
        "-p",
        "--model",
        "claude-sonnet-4-5",
        // `=`: the flag takes several values, and would take the prompt as one.
        "--allowedTools=Bash(vox agent status:*)",
        "hello",
    ];
    let claude_env = [
        ("ANTHROPIC_BASE_URL", url.as_str()),
        ("ANTHROPIC_API_KEY", "made-up-key-for-a-stand-in"),
        (
            "CLAUDE_CODE_TMPDIR",
            t.to_str().expect("APPARATUS: a UTF-8 path"),
        ),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ("DISABLE_AUTOUPDATER", "1"),
    ];
    let (sent, said) = turn("Claude Code", &claude, &claude_args, &claude_env);
    loaded("Claude Code", &sent, std::slice::from_ref(&skill_line));
    no_node("Claude Code", "claude", &said);
    connect("claude", "claude-proof");
    let (sent, said) = turn("Claude Code", &claude, &claude_args, &claude_env);
    loaded("Claude Code", &sent, std::slice::from_ref(&skill_line));
    no_room("Claude Code", "claude-proof", &sent, &said);

    let codex_home = home.join(".codex");
    let codex_env = [
        (
            "CODEX_HOME",
            codex_home.to_str().expect("APPARATUS: a UTF-8 path"),
        ),
        ("STANDIN_API_KEY", "made-up-key-for-a-stand-in"),
    ];
    let codex_args = [
        "exec",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "hello",
    ];
    let (sent, said) = turn("Codex", &codex, &codex_args, &codex_env);
    loaded("Codex", &sent, std::slice::from_ref(&skill_line));
    no_node("Codex", "codex", &said);
    connect("codex", "codex-proof");
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
    let (sent, said) = turn("Codex", &codex, &codex_args, &codex_env);
    loaded("Codex", &sent, std::slice::from_ref(&skill_line));
    no_room("Codex", "codex-proof", &sent, &said);

    let xdg = |d: &str| root.join("xdg").join(d).display().to_string();
    let config = home.join(".config").display().to_string();
    let (xdg_data, xdg_state, xdg_cache) = (xdg("data"), xdg("state"), xdg("cache"));
    let opencode_env = [
        ("XDG_CONFIG_HOME", config.as_str()),
        ("XDG_DATA_HOME", xdg_data.as_str()),
        ("XDG_STATE_HOME", xdg_state.as_str()),
        ("XDG_CACHE_HOME", xdg_cache.as_str()),
        ("OPENCODE_DISABLE_MODELS_FETCH", "1"),
        ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
        ("OPENCODE_DISABLE_LSP_DOWNLOAD", "1"),
        // Its Claude Code compatibility would read ~/.claude/skills, where Claude Code's
        // copy of the pack could stand in for OpenCode's own.
        ("OPENCODE_DISABLE_CLAUDE_CODE", "1"),
    ];
    let opencode_args = ["run", "--model", "standin/stub-model", "hello"];
    let opencode_listed = [
        "<name>vox-agent-comms</name>".to_owned(),
        format!("<description>{description}"),
    ];
    let (sent, said) = turn("OpenCode", &opencode, &opencode_args, &opencode_env);
    loaded("OpenCode", &sent, &opencode_listed);
    no_node("OpenCode", "opencode", &said);
    connect("opencode", "opencode-proof");
    let (sent, said) = turn("OpenCode", &opencode, &opencode_args, &opencode_env);
    loaded("OpenCode", &sent, &opencode_listed);
    no_room("OpenCode", "opencode-proof", &sent, &said);

    // ---- (5) the room: the operator's part, as the pack gives it to them ----
    // A person's node `alice` makes the room; each harness's node joins it with the command the
    // pack gives the operator (Claude Code's binding this repo); each pair trusts the other to
    // read, typed at a terminal as the pack says; Claude Code's node gives alice drive as it
    // trusts her, and OpenCode's node gives Codex's drive.
    let staged = |what: &str, args: &[&str]| -> String {
        let (ok, out, err) = vox(args);
        assert!(
            ok,
            "APPARATUS (staging): `vox {}` ({what}) failed: {out}{err}",
            args.join(" ")
        );
        out + &err
    };
    let rpass = root.join("room.pass");
    std::fs::write(&rpass, "room passphrase\n").expect("APPARATUS: the room passphrase file");
    let rpass_arg = rpass.to_str().expect("APPARATUS: a UTF-8 path");
    staged("alice", &["node", "create", "alice", "--passphrase-file", pass_arg]);
    staged("alice", &["node", "attach", "alice", "--passphrase-file", pass_arg]);
    staged(
        "the room",
        &["room", "create", "--node", "alice", "--name", "work", "--passphrase-file", rpass_arg],
    );
    let room = staged("the room", &["room", "list", "--node", "alice"])
        .split_whitespace()
        .next()
        .expect("APPARATUS (staging): `vox room list` shows no room")
        .to_owned();
    let link = staged("the link", &["room", "link", &room, "--node", "alice"])
        .lines()
        .find(|l| l.starts_with("vox://"))
        .expect("APPARATUS (staging): `vox room link` printed no link")
        .to_owned();
    let repo_arg = repo.to_str().expect("APPARATUS: a UTF-8 path");
    // setup.md: `vox room join <link> --node <your node> --bind <this repo's directory>`, its
    // passphrase from a file here where the operator types it.
    let (ok, out, err) = vox(&[
        "room", "join", &link, "--node", "claude-proof", "--bind", repo_arg,
        "--passphrase-file", rpass_arg,
    ]);
    println!("[proof] the operator's join, as the pack gives it:\n{out}{err}");
    assert!(
        ok,
        "PRODUCT: the join the pack gives the operator (`vox room join <link> --node \
         claude-proof --bind <repo>`) failed: {out}{err}"
    );
    for node in ["codex-proof", "opencode-proof"] {
        let (ok, out, err) =
            vox(&["room", "join", &link, "--node", node, "--passphrase-file", rpass_arg]);
        assert!(
            ok,
            "PRODUCT: the join the pack gives the operator (`vox room join <link> --node \
             {node}`, without --bind) failed: {out}{err}"
        );
    }
    let nodes = ["alice", "claude-proof", "codex-proof", "opencode-proof"];
    let fp: BTreeMap<&str, String> = nodes
        .iter()
        .map(|n| (*n, staged("its id", &["id", "--node", n]).trim().to_owned()))
        .collect();
    // A keyring change is typed at a terminal (trust.md), as a person types it.
    let typed_vox = |args: &[&str]| -> (bool, String) {
        let mut c = Command::new(&vox_bin);
        env(&mut c);
        c.args(args);
        typed::typed(&c, "identity passphrase")
    };
    for a in nodes {
        for b in nodes.iter().filter(|b| **b != a) {
            // trust.md: `vox trust add <fingerprint> --name <name> --drive`, for one of them.
            let mut args = vec!["trust", "add", &fp[b], "--name", b, "--node", a];
            if (a, *b) == ("claude-proof", "alice") {
                args.push("--drive");
            }
            let (ok, shown) = typed_vox(&args);
            assert!(
                ok,
                "APPARATUS (staging): `vox trust add {b} --node {a}` failed: {shown}"
            );
        }
    }
    // trust.md: `vox trust drive <fingerprint>`, the operator's, at a terminal.
    let (ok, shown) = typed_vox(&["trust", "drive", &fp["codex-proof"], "--node", "opencode-proof"]);
    println!("[proof] the operator's `vox trust drive`, typed:\n{shown}");
    assert!(
        ok,
        "PRODUCT: `vox trust drive <fingerprint>`, typed at a terminal as trust.md says, failed: \
         {shown}"
    );
    // A message for Claude Code's node to answer, and a file for every member.
    staged(
        "alice's ask",
        &["room", "post", &room, "--node", "alice", "--to", "claude-proof", "how is the codec going?"],
    );
    let read = staged("alice's read", &["room", "read", &room, "--node", "alice"]);
    let asked = read
        .lines()
        .find(|l| l.contains("how is the codec going?"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("APPARATUS (staging): alice's read shows no ask:\n{read}"))
        .to_owned();
    std::fs::write(root.join("notes.txt"), "notes for every member\n")
        .expect("APPARATUS: the shared file");
    let notes = root.join("notes.txt");
    staged(
        "alice's share",
        &["share", &room, notes.to_str().expect("APPARATUS: a UTF-8 path"), "-m", "notes for all",
          "--node", "alice"],
    );
    std::fs::write(repo.join("report.json"), "{\"codec\": \"on track\"}\n")
        .expect("APPARATUS: the report");
    std::fs::write(repo.join("spec.md"), "# the codec\n").expect("APPARATUS: the spec");
    std::fs::create_dir_all(repo.join("incoming")).expect("APPARATUS: incoming");

    // ---- (6) each harness runs the pack's commands, as written, through its own shell ----
    // What each turn ran: the stand-in writes each command with what the harness gave back.
    let script = |key: &str, lines: &[String]| {
        std::fs::write(script_dir.join(format!("{key}.cmds")), lines.join("\n") + "\n")
            .expect("APPARATUS: the stand-in's script");
    };
    let ran = |name: &str, key: &str, lines: &[String]| -> Vec<String> {
        let _ = std::fs::remove_file(script_dir.join(format!("{key}.cmds")));
        let text = std::fs::read_to_string(script_dir.join(format!("{key}.ran")))
            .unwrap_or_else(|e| {
                panic!("APPARATUS: {name} did not run the script through its shell tool ({e})")
            });
        let outs: Vec<String> = text
            .split("\n### ")
            .skip(1)
            .map(|s| s.split_once('\n').map_or("", |(_, o)| o).to_owned())
            .collect();
        assert_eq!(
            outs.len(),
            lines.len(),
            "APPARATUS: {name} ran {} of the {} commands:\n{text}",
            outs.len(),
            lines.len()
        );
        for (c, o) in lines.iter().zip(&outs) {
            println!("[proof] {name} $ {c}\n{}", o.trim_end());
        }
        outs
    };
    // The command at `i` ran, exited 0, and said each of `want`.
    let said_ok = |name: &str, lines: &[String], outs: &[String], i: usize, want: &[&str]| {
        let o = &outs[i];
        assert!(
            o.contains("[exit 0]") && want.iter().all(|w| o.contains(w)),
            "PRODUCT: `{}`, run by {name} as the pack writes it, was to exit 0 saying {want:?}; \
             it said:\n{o}",
            lines[i]
        );
    };
    let said_refused = |name: &str, lines: &[String], outs: &[String], i: usize, want: &[&str]| {
        let o = &outs[i];
        assert!(
            !o.contains("[exit 0]") && want.iter().all(|w| o.contains(w)),
            "PRODUCT: `{}`, run by {name}, was to be refused saying {want:?}; it said:\n{o}",
            lines[i]
        );
    };
    let codec = "gwa:acme/widgets:prd-1:codec";
    let wire = "gwa:acme/widgets:prd-1:wire";

    let sessions_of = |node: &str| -> Vec<serde_json::Value> {
        staged("the Sessions", &["room", "sessions", &room, "--json", "--node", "alice"])
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["node"].as_str() == Some(fp[node].as_str()))
            .collect()
    };

    let claude_ran = [
        "-p",
        "--model",
        "claude-sonnet-4-5",
        "--allowedTools=Bash",
        "hello",
    ];
    // OpenCode: `VOX_NODE` set for it. Its session stays open, its last command waiting on the
    // proof, so the other two find its Session open: Codex's node holds drive over it, Claude
    // Code's does not.
    let release = root.join("release");
    let opencode_lines: Vec<String> = vec![
        "vox agent status --harness opencode".to_owned(),
        "vox trust list".to_owned(),
        format!("vox room sessions {room}"),
        format!("until [ -e {} ]; do sleep 1; done", release.display()),
    ];
    script("opencode", &opencode_lines);
    let opencode_session = std::thread::scope(|scope| {
        // However this scope ends, a red included, OpenCode's last command is let go, so its
        // turn ends and the scope can join it.
        let let_go = Release(release.clone());
        let held = scope.spawn(|| turn("OpenCode", &opencode, &opencode_args, &opencode_env));
        let deadline = Instant::now() + Duration::from_secs(300);
        let opencode_session = loop {
            if let Some(id) = sessions_of("opencode-proof")
                .iter()
                .find(|v| v["open"] == serde_json::Value::Bool(true))
                .and_then(|v| v["id"].as_str().map(str::to_owned))
            {
                break id;
            }
            assert!(
                Instant::now() < deadline && !held.is_finished(),
                "PRODUCT: OpenCode's session worked in the room and no open Session of node \
                 opencode-proof showed there in 300 s (alice's `vox room sessions --json`)"
            );
            std::thread::sleep(Duration::from_millis(500));
        };
        let s = &opencode_session;

        // Codex: no `VOX_NODE`, so each command names the node, as SKILL.md says, but for `vox
        // agent status`, which takes the harness.
        let x = "--node codex-proof";
        let lines: Vec<String> = vec![
            "vox agent status --harness codex".to_owned(),
            format!("vox room list {x}"),
            format!("vox trust list {x}"),
            format!("vox room claim {room} {x} --work \"{codec}\" --ttl 3600 --op skill-proof-1"),
            format!("vox room claim {room} {x} --work \"{codec}\" --ttl 3600 --op skill-proof-1"),
            format!("vox room claim {room} {x} --work \"{wire}\" --ttl 3600"),
            format!("vox room handoff {room} {x} \"{wire}\" --to {}", &fp["claude-proof"][..8]),
            format!(
                "vox room post {room} {x} --type ask --to alice --work \"{codec}\" \"how is it going?\""
            ),
            format!("vox room post {room} {x} --type blocked \"the codec test fails only on Linux\""),
            format!("vox room post {room} {x} --urgent --to claude-proof \"blocked on your answer\""),
            format!("vox room board {room} {x}"),
            format!("vox room sessions {room} {x} --json"),
            format!("vox room session {room} {x} {s}"),
            format!("vox room session {room} {x} {s} --details"),
            format!("vox room session {room} {x} {s} --say \"carry on with e2\""),
            format!("vox room session {room} {x} {s} --file ./spec.md --note \"read this first\""),
            format!("vox room ping {room} {x} opencode-proof"),
        ];
        script("codex", &lines);
        let (_, _) = turn("Codex", &codex, &codex_args, &codex_env);
        let outs = ran("Codex", "codex", &lines);
        let n = "Codex";
        said_ok(n, &lines, &outs, 1, &[&room]);
        said_ok(n, &lines, &outs, 2, &["opencode-proof  read\n", "claude-proof  read\n"]);
        for i in 3..=10 {
            said_ok(n, &lines, &outs, i, &[]);
        }
        said_ok(n, &lines, &outs, 10, &[codec, wire]);
        // rooms.md: a post says, for each node it addresses, what to expect.
        said_ok(n, &lines, &outs, 7, &["to alice: ", "you trust it; it trusts you"]);
        let open_with_drive = format!("\"id\":\"{s}\"");
        assert!(
            outs[11].lines().any(|l| l.contains(&open_with_drive)
                && l.contains("\"open\":true")
                && l.contains("\"can_drive\":true")),
            "PRODUCT: Codex's node holds drive from OpenCode's, and `vox room sessions --json` did \
             not say `\"can_drive\":true` for OpenCode's open Session {s}:\n{}",
            outs[11]
        );
        said_ok(n, &lines, &outs, 12, &[]);
        said_ok(n, &lines, &outs, 13, &[]);
        for i in [12, 13, 14, 15] {
            assert!(
                !outs[i].contains("trusts with drive see inside")
                    && !outs[i].contains("does not trust you with drive"),
                "PRODUCT: `{}`: Codex's node holds drive from OpenCode's, yet it was refused for \
                 want of it:\n{}",
                lines[i],
                outs[i]
            );
        }
        said_ok(n, &lines, &outs, 16, &[]);

        // Claude Code: `VOX_NODE` set for it, so no command names its node, though four are
        // attached here; OpenCode's node trusts it to read only.
        let lines: Vec<String> = vec![
            "vox agent status --harness claude".to_owned(),
            "vox room list".to_owned(),
            "vox id".to_owned(),
            "vox trust list".to_owned(),
            "vox trust offers".to_owned(),
            format!("vox room roster {room}"),
            format!("vox room read {room}"),
            format!("vox room post {room} --re {asked} \"on track, not stuck\""),
            format!(
                "vox room post {room} \"the codec test fails only on Linux; has anyone seen this?\""
            ),
            format!(
                "echo \"can you take the wire codec?\" | vox room post {room} --type assign --to \
                 alice --work \"{codec}\" -"
            ),
            format!("vox room decline {room} \"{wire}\""),
            format!("vox room claim {room} --work \"{wire}\" --ttl 3600"),
            format!("vox room board {room}"),
            format!("vox room renew {room} \"{wire}\""),
            format!("vox room release {room} \"{wire}\""),
            format!("vox room sessions {room} --json"),
            format!("vox room session {room} {s}"),
            format!("vox room session {room} {s} --say \"carry on with e2\""),
            format!("vox room ping {room} opencode-proof"),
            format!("vox share {room} ./report.json --to alice -m \"the report you asked for\""),
            format!("vox share list {room}"),
            format!("vox share stop {room} report.json"),
            "vox agent send ./report.json --note \"the numbers you asked for\"".to_owned(),
            "vox agent doctor".to_owned(),
            format!("vox agent room {room}"),
            format!(
                "vox trust drive {} --identity-passphrase-file ./report.json",
                fp["codex-proof"]
            ),
        ];
        script("claude", &lines);
        let (sent, _) = turn("Claude Code", &claude, &claude_ran, &claude_env);
        let outs = ran("Claude Code", "claude", &lines);
        let n = "Claude Code";
        assert!(
            sent.contains("how is the codec going?"),
            "PRODUCT: Claude Code's turn did not carry alice's message from the room: the hook is \
             to drain every room into the turn; the lines naming vox were:\n{}",
            vox_lines(&sent)
        );
        said_ok(n, &lines, &outs, 1, &[&room]);
        said_ok(n, &lines, &outs, 2, &[&fp["claude-proof"]]);
        said_ok(
            n,
            &lines,
            &outs,
            3,
            &["codex-proof  read\n", "opencode-proof  read\n", "alice  read + drive"],
        );
        for i in [4, 5, 7, 8, 9, 10, 11, 13, 14] {
            said_ok(n, &lines, &outs, i, &[]);
        }
        said_ok(n, &lines, &outs, 6, &["how is the codec going?"]);
        said_ok(n, &lines, &outs, 12, &[wire]);
        assert!(
            outs[15].lines().any(|l| l.contains(&open_with_drive)
                && l.contains("\"can_drive\":false")),
            "PRODUCT: Claude Code's node holds no drive from OpenCode's, and `vox room sessions \
             --json` did not say `\"can_drive\":false` for OpenCode's Session {s}:\n{}",
            outs[15]
        );
        said_ok(
            n,
            &lines,
            &outs,
            16,
            &["Only members opencode-proof trusts with drive see inside this Session."],
        );
        said_refused(n, &lines, &outs, 17, &["does not trust you with drive"]);
        for i in 18..lines.len() - 1 {
            said_ok(n, &lines, &outs, i, &[]);
        }
        // trust.md: a keyring change's passphrase is typed at a terminal, and Vox takes it from
        // nothing else, a file included. (The pack does not claim the session is refused: for 30
        // minutes after the operator typed it, the node asks for it no more.)
        said_refused(
            n,
            &lines,
            &outs,
            lines.len() - 1,
            &["typed at a terminal, never read from a file"],
        );

        drop(let_go);
        held.join().expect("APPARATUS: OpenCode's turn panicked");
        opencode_session
    });
    let outs = ran("OpenCode", "opencode", &opencode_lines);
    let n = "OpenCode";
    let lines = &opencode_lines;
    said_ok(n, lines, &outs, 1, &["codex-proof  read + drive", "claude-proof  read\n"]);
    said_ok(n, lines, &outs, 2, &[&opencode_session[..8]]);
    said_ok(n, lines, &outs, 3, &[]);
    // files.md: `vox room get`. It reaches the daemon's forward on an ephemeral loopback port,
    // which the harness's sandbox keeps closed (it opens no loopback port but the stand-in's), so
    // it runs here as Claude Code's node, in the repo, as the agent would run it.
    let mut c = Command::new(&vox_bin);
    env(&mut c);
    let got = c
        .args(["room", "get", &room, "notes.txt", "--dir", "./incoming"])
        .env("VOX_NODE", "claude-proof")
        .current_dir(&repo)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox room get: {e}"));
    let said = String::from_utf8_lossy(&got.stdout).into_owned()
        + &String::from_utf8_lossy(&got.stderr);
    println!("[proof] Claude Code's node $ vox room get {room} notes.txt --dir ./incoming\n{said}");
    assert!(
        got.status.success()
            && said.contains("matches its announced SHA-256")
            && std::fs::read_to_string(repo.join("incoming/notes.txt")).is_ok_and(|t| t == "notes for every member\n"),
        "PRODUCT: `vox room get <room> notes.txt --dir ./incoming`, as files.md writes it, did not \
         put alice's file there verified; it said:\n{said}"
    );
    drop(stop);
}
