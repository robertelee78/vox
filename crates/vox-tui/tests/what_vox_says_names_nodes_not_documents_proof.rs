//! **What `vox` says names the node, and no design document** — driven through the shipped binary.
//!
//! The node replaced the profile (ADR-026), but help and messages still said "profile" where they
//! meant the node; `vox up --help` showed the withdrawn address form `ssh nas.family.vox`; and
//! `vox status` told people "unknown: not recorded until ADR-023". A person reads none of the
//! design documents, so a reference to one tells them nothing.
//!
//! Asserted, over the help of **every** subcommand (walked from `vox --help`, as clap lists them)
//! and over what a running node says to `vox status`, `vox status --json` and a room it does not
//! hold:
//! - no "profile" (the node's old name);
//! - no reference to a design document (`ADR-…`, `PRD-…`, `V030-…`, `V210-…`, `M17.…`, `(#…)`);
//! - every example `.vox` address has the one form that connects, `<service>.<node>.<room>.vox`:
//!   four labels.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::{Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the wording proof";

fn vox(data: &Path, argv: &[&str]) -> (bool, String) {
    let out = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data.join("data"))
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox {argv:?}: {e}"));
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Every help page, `(command, text)`, walking the `Commands:` lists from the top.
fn every_help(data: &Path) -> Vec<(String, String)> {
    let mut pages = Vec::new();
    let mut todo: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(cmd) = todo.pop() {
        let mut argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
        argv.push("--help");
        let (_, text) = vox(data, &argv);
        let mut listing = false;
        for line in text.lines() {
            if line.starts_with("Commands:") {
                listing = true;
                continue;
            }
            if line.starts_with("Options:") || line.starts_with("Arguments:") {
                listing = false;
            }
            let Some(sub) = line
                .strip_prefix("  ")
                .and_then(|l| l.split_whitespace().next())
            else {
                continue;
            };
            if listing && !line.starts_with("   ") && sub != "help" {
                let mut next = cmd.clone();
                next.push(sub.to_owned());
                todo.push(next);
            }
        }
        pages.push((format!("vox {}", cmd.join(" ")), text));
    }
    pages
}

/// What in `text` names the profile or a design document, or gives an address of another form.
fn faults(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let low = line.to_ascii_lowercase();
        if low.contains("profile") && !low.contains("bash_profile") {
            out.push(format!("says \"profile\": {}", line.trim()));
        }
        let refs = ["ADR-", "PRD-", "V030-", "V210-", "V29-", "M17.", "(#"];
        if let Some(r) = refs.iter().find(|r| line.contains(**r)) {
            out.push(format!("names a design document ({r}…): {}", line.trim()));
        }
        for word in line.split(|c: char| c.is_whitespace() || "`'\"(),;".contains(c)) {
            let host = word.trim_end_matches(['.', ':']);
            let host = host.split(':').next().unwrap_or(host);
            let host = host.rsplit('@').next().unwrap_or(host);
            if let Some(name) = host.strip_suffix(".vox") {
                if !name.is_empty() && !name.contains('/') && name.split('.').count() != 3 {
                    out.push(format!(
                        "gives the address {host:?}, not <service>.<node>.<room>.vox: {}",
                        line.trim()
                    ));
                }
            }
        }
    }
    out
}

#[test]
#[ignore = "a vox daemon with production Argon2id; CI runs it in release"]
fn help_and_messages_name_the_node_and_no_design_document() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    std::fs::create_dir_all(tmp.path().join("cfg")).expect("APPARATUS: no config dir");

    let pages = every_help(tmp.path());
    assert!(
        pages.len() > 40 && pages.iter().any(|(c, _)| c == "vox up"),
        "APPARATUS: the help walk found {} pages, so it did not walk the commands",
        pages.len()
    );

    // A running node, as a person has one: `vox status` and a room it does not hold.
    let (ok, said) = vox(tmp.path(), &["node", "create", "a"]);
    assert!(ok, "PRODUCT (staging): vox node create a: {said}");
    let pass = tmp.path().join("pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: passphrase file");
    let (ok, said) = vox(
        tmp.path(),
        &[
            "node",
            "attach",
            "a",
            "--passphrase-file",
            pass.to_str().expect("utf-8"),
        ],
    );
    assert!(ok, "PRODUCT (staging): vox node attach a: {said}");
    let mut said_by_node = Vec::new();
    for argv in [
        &["status"][..],
        &["status", "--json"],
        &["room", "read", "nosuchroom"],
    ] {
        let (_, text) = vox(tmp.path(), argv);
        said_by_node.push((format!("vox {}", argv.join(" ")), text));
    }
    let _ = vox(tmp.path(), &["node", "detach", "a"]);

    let mut all = Vec::new();
    for (cmd, text) in pages.iter().chain(&said_by_node) {
        for f in faults(text) {
            all.push(format!("{cmd}: {f}"));
        }
    }
    println!(
        "[proof] {} help pages and {} node answers read; faults: {}",
        pages.len(),
        said_by_node.len(),
        all.len()
    );
    assert!(
        said_by_node
            .iter()
            .any(|(c, t)| c == "vox status" && t.contains("always-on member")),
        "PRODUCT (staging): `vox status` did not answer with its report: {said_by_node:?}"
    );
    assert!(
        all.is_empty(),
        "PRODUCT: what vox says must name the node, not the profile, name no design document, and \
         give addresses as <service>.<node>.<room>.vox:\n{}",
        all.join("\n")
    );
}
