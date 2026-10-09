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

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
