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
//! Prose that merely mentions the word `vox` is not a command and is not checked.

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
        .output()
        .expect("run vox");
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

#[test]
fn every_verb_and_flag_the_skill_names_exists_in_the_cli() {
    let (ok, skill) = vox(&["agent", "skill"]);
    assert!(ok, "vox agent skill must print the skill: {skill}");
    let (cmds, bare) = extract(&skill);
    assert!(
        cmds.len() >= 10,
        "the extractor must find the skill's commands, or this gate proves nothing: {cmds:?}"
    );

    let mut help: BTreeMap<Vec<String>, String> = BTreeMap::new();
    let mut problems = Vec::new();
    for c in &cmds {
        for path in &c.paths {
            let h = help.entry(path.clone()).or_insert_with(|| {
                let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
                args.push("--help");
                let (ok, out) = vox(&args);
                if ok {
                    out
                } else {
                    String::new()
                }
            });
            if h.is_empty() {
                problems.push(format!(
                    "`vox {}` is not a command (from: {})",
                    path.join(" "),
                    c.source
                ));
                continue;
            }
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
        "the extractor must find the skill's bare flags, or this half proves nothing: {bare:?}"
    );
    for (f, section) in &bare {
        let local: Vec<&Vec<String>> = cmds
            .iter()
            .filter(|c| c.section == *section)
            .flat_map(|c| c.paths.iter())
            .collect();
        let found = if local.is_empty() {
            help.values().any(|h| has_flag(h, f))
        } else {
            local
                .iter()
                .any(|p| help.get(*p).is_some_and(|h| has_flag(h, f)))
        };
        if !found {
            problems.push(format!(
                "the skill names {f} in a section whose verbs ({local:?}) do not have it"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "the skill names what the CLI does not have:\n  {}",
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
