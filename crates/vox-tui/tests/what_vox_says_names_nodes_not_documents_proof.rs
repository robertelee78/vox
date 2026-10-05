//! **What `vox` says names the node, and no design document** — driven through the shipped binary.
//!
//! The node replaced the profile (ADR-026), but help and messages still said "profile" where they
//! meant the node; `vox up --help` showed the withdrawn address form `ssh nas.family.vox`; and
//! `vox status` told people "unknown: not recorded until ADR-023". A person reads none of the
//! design documents, so a reference to one tells them nothing.
//!
//! Asserted, over the help of **every** subcommand (walked from `vox --help`, as clap lists them)
//! and over what a running node says to `vox status`, `vox status --json`, a room it does not
//! hold, `vox room link` and `vox serve`:
//! - no "profile" (the node's old name);
//! - no "channel" and no "consent": a person has rooms, and trusts a member (#406);
//! - no "invite": a room has a room link, which `vox room link` prints; `vox room invite` is
//!   refused as an unknown command (#406);
//! - no reference to a design document (`ADR-…`, `PRD-…`, `V030-…`, `V210-…`, `M17.…`, `(#…)`);
//! - every example `.vox` address has the one form that connects, `<service>.<node>.<room>.vox`:
//!   four labels.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::BufRead;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

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
        if let Some(w) = ["channel", "consent", "invite"]
            .iter()
            .find(|w| low.contains(**w))
        {
            out.push(format!("says \"{w}\": {}", line.trim()));
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

/// What `vox serve` prints up to the passphrase advice and the line after it: it keeps running,
/// so it is stopped once that is read, or after 60 s.
fn serve_says(data: &Path) -> String {
    let mut child = Command::new(VOX)
        .args(["serve", "web=9", "--name", "served"])
        .env("VOX_DATA_DIR", data.join("data"))
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox serve: {e}"));
    let stdout = child.stdout.take().expect("APPARATUS: piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut said = String::new();
    let mut advice = false;
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(60)) {
        said.push_str(&line);
        said.push('\n');
        if advice {
            break;
        }
        advice = line.trim_start().starts_with('^');
    }
    let _ = child.kill();
    let _ = child.wait();
    said
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
    // A room and its link, as a person shares one: the advice on sending the passphrase.
    let room_pass = tmp.path().join("room-pass");
    std::fs::write(&room_pass, "room passphrase for the wording proof\n")
        .expect("APPARATUS: room passphrase file");
    let room_pass = room_pass.to_str().expect("utf-8");
    let (ok, said) = vox(
        tmp.path(),
        &[
            "room",
            "create",
            "--passphrase-file",
            room_pass,
            "--name",
            "words",
        ],
    );
    assert!(ok, "PRODUCT (staging): vox room create: {said}");
    // The room by its id, as `vox room list` names it first.
    let (_, listed) = vox(tmp.path(), &["room", "list"]);
    let room: String = listed
        .lines()
        .find(|l| l.contains("words"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    let (ok, said) = vox(tmp.path(), &["room", "link", &room]);
    assert!(
        ok,
        "PRODUCT (staging): vox room link {room}: {said}\n{listed}"
    );
    said_by_node.push(("vox room link words".into(), said));
    // The old verb is gone, with no alias: clap refuses it as a command it does not know.
    let (ok, said) = vox(tmp.path(), &["room", "invite", &room]);
    assert!(
        !ok && said.contains("unrecognized subcommand 'invite'"),
        "PRODUCT: `vox room invite` must be refused as an unknown command, not run: ok {ok}: {said}"
    );
    said_by_node.push(("vox serve web=9".into(), serve_says(tmp.path())));
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
        said_by_node
            .iter()
            .filter(|(c, _)| ["vox room link words", "vox serve web=9"].contains(&c.as_str()))
            .all(|(_, t)| t.contains("passphrase")),
        "PRODUCT (staging): `vox room link` or `vox serve` said nothing of the passphrase: \
         {said_by_node:?}"
    );
    assert!(
        all.is_empty(),
        "PRODUCT: what vox says must name the node, not the profile, say room and trust, not channel \
         or consent, name no design document, and \
         give addresses as <service>.<node>.<room>.vox:\n{}",
        all.join("\n")
    );
}
