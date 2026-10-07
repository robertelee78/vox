//! V030-35 D4 (#402) — **every piece of process-wide state is listed** (ADR-026 P-1, §10 proof 13).
//!
//! A process may host several nodes, so state kept once per process is shared by all of them. That
//! is right for a few things (a counter that only has to be unique, mlock bookkeeping) and a leak
//! for the rest (one node's tunnels, counts or settings seen or used by another). ADR-026 P-1
//! lists each `static`, `OnceLock`, `Once` and module-level atomic in `vox-core` and `vox-tui`
//! with its disposition, and requires a check that enumerates them against that table, so that a
//! new one is a deliberate decision rather than an accident.
//!
//! This is that check. It reads every `.rs` file under `crates/vox-core/src` and
//! `crates/vox-tui/src`, finds each `static` item (at module level or inside a function: a
//! function's static is just as process-wide), each `thread_local!` and each `lazy_static!`, and
//! requires each to be in [`LISTED`] under its ADR row, as many times as the file has it. A
//! listed one that is gone is red too, so the table never claims what the code no longer has.
//!
//! A `OnceLock` or atomic **field** of a struct is per value, not per process, and is not listed;
//! only a `static` holding one is.
//!
//! **Which side a red is on.** An unlisted static is `PRODUCT:` — process-wide state nobody
//! decided on. A listed one that is gone is `PRODUCT (table):` — the table is stale. A source
//! tree that cannot be read is `APPARATUS:`.
//!
//! Mutant: add a `static` anywhere in vox-core → red, naming its file and line.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The ADR-026 P-1 rows, by the words the ADR uses.
mod row {
    pub const TUNNELS: &str =
        "LIVE, CLOSED tunnels (quic.rs): per owning node; every reader filters";
    pub const REACH_COUNTS: &str = "DIAL_BACKS, OUTBOUND_CIRCUITS: keyed (local node, peer)";
    pub const FINISHING: &str = "FINISHING (tunnel/session.rs): per node; daemon stop waits on all";
    pub const NAMES: &str = "ident::NAMES, ident::ME (vox-tui): removed; names passed explicitly";
    pub const TEST_KNOB_ROOM: &str =
        "test-knob maps by room (actor.rs), the LEFT counter: keyed (node, room)";
    pub const TEST_KNOB_ENV: &str =
        "test-knob environment OnceLocks (prekeys.rs, channel.rs, log/sync.rs, nat/store.rs, \
         ipc.rs): process-wide, test builds only";
    pub const COUNTERS: &str =
        "NEXT_TUNNEL, NEXT_SERIAL, paths::NEXT: process-wide unique counters";
    pub const PINNED: &str = "PINNED (atrest/lock.rs): process-wide mlock bookkeeping";
    pub const CACHED: &str = "SAID (quic.rs), cached strings (api.rs, viewmodel.rs): process-wide";
    pub const SENDING: &str =
        "SENDING (claude_injector.rs): process-wide, one tmux send at a time across nodes";
}

/// Every process-wide item: (file under `crates/`, name, how many the file has, its ADR row,
/// and, for a row whose disposition the code does not meet yet, the work that will).
const LISTED: &[(&str, &str, usize, &str, Option<&str>)] = &[
    ("vox-core/src/transport/quic.rs", "LIVE", 1, row::TUNNELS, None),
    ("vox-core/src/transport/quic.rs", "CLOSED", 1, row::TUNNELS, None),
    ("vox-core/src/transport/quic.rs", "NEXT_TUNNEL", 1, row::COUNTERS, None),
    ("vox-core/src/transport/quic.rs", "NEXT_SERIAL", 1, row::COUNTERS, None),
    ("vox-core/src/transport/quic.rs", "SAID", 1, row::CACHED, None),
    ("vox-core/src/node/coordstream.rs", "DIAL_BACKS", 1, row::REACH_COUNTS, None),
    ("vox-core/src/node/circuitstream.rs", "OUTBOUND_CIRCUITS", 1, row::REACH_COUNTS, None),
    ("vox-core/src/tunnel/session.rs", "FINISHING", 1, row::FINISHING, None),
    ("vox-core/src/node/actor.rs", "FIRST", 2, row::TEST_KNOB_ROOM, None),
    ("vox-core/src/node/actor.rs", "LEFT", 1, row::TEST_KNOB_ROOM, None),
    ("vox-core/src/node/prekeys.rs", "POOL", 1, row::TEST_KNOB_ENV, None),
    ("vox-core/src/node/channel.rs", "MAX", 1, row::TEST_KNOB_ENV, None),
    ("vox-core/src/log/sync.rs", "MODE", 1, row::TEST_KNOB_ENV, None),
    ("vox-core/src/nat/store.rs", "TTL", 1, row::TEST_KNOB_ENV, None),
    ("vox-core/src/node/ipc.rs", "LIMIT", 1, row::TEST_KNOB_ENV, None),
    ("vox-core/src/node/paths.rs", "NEXT", 1, row::COUNTERS, None),
    ("vox-core/src/atrest/lock.rs", "PINNED", 1, row::PINNED, None),
    ("vox-core/src/node/api.rs", "TEXT", 1, row::CACHED, None),
    ("vox-tui/src/viewmodel.rs", "TEXT", 1, row::CACHED, None),
    ("vox-tui/src/claude_injector.rs", "SENDING", 1, row::SENDING, None),
    (
        "vox-tui/src/ident.rs",
        "NAMES",
        1,
        row::NAMES,
        Some("NOT DONE: still here, set only by client processes' `load_names`; #402 did not remove it"),
    ),
    (
        "vox-tui/src/ident.rs",
        "ME",
        1,
        row::NAMES,
        Some("NOT DONE: still here, set only by client processes' `load_names`; #402 did not remove it"),
    ),
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("APPARATUS: directory entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The name a line declares as process-wide state, if it declares one: `static NAME`, with any
/// visibility and `mut`, or a `thread_local!` / `lazy_static!` block's opening (named by the
/// macro, since its statics follow on later lines).
fn declared(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with("//") {
        return None;
    }
    if t.starts_with("thread_local!") || t.starts_with("lazy_static!") {
        return Some(t.split('!').next().unwrap_or_default().to_owned());
    }
    let mut rest = t;
    if let Some(r) = rest.strip_prefix("pub") {
        rest = r.trim_start();
        if rest.starts_with('(') {
            rest = rest.split_once(')').map_or("", |(_, r)| r).trim_start();
        }
    }
    let rest = rest.strip_prefix("static ")?.trim_start();
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    // `static` in a type or bound (`&'static`, `T: 'static`) never starts a line this way; a
    // name must be followed by its type.
    rest[name.len()..]
        .trim_start()
        .starts_with(':')
        .then_some(name)
        .filter(|n| !n.is_empty())
}

#[test]
#[ignore = "source check for ADR-026 P-1 (#402); run on demand"]
fn every_process_wide_state_is_listed() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("APPARATUS: crates directory")
        .to_path_buf();
    let mut files = Vec::new();
    for root in ["vox-core/src", "vox-tui/src"] {
        rs_files(&crates.join(root), &mut files);
    }
    files.sort();
    assert!(
        files.len() > 50,
        "APPARATUS: only {} source files found under {}",
        files.len(),
        crates.display()
    );

    // (file, name) → the lines it is declared on.
    let mut found: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for file in &files {
        let rel = file
            .strip_prefix(&crates)
            .expect("APPARATUS: path under crates")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot read {rel}: {e}"));
        for (i, line) in text.lines().enumerate() {
            if let Some(name) = declared(line) {
                found.entry((rel.clone(), name)).or_default().push(i + 1);
            }
        }
    }

    let mut reds = Vec::new();
    let mut listed: BTreeMap<(String, String), (usize, &str, Option<&str>)> = BTreeMap::new();
    for (file, name, count, row, pending) in LISTED {
        listed.insert(
            ((*file).to_owned(), (*name).to_owned()),
            (*count, row, *pending),
        );
    }
    for ((file, name), lines) in &found {
        match listed.get(&(file.clone(), name.clone())) {
            None => reds.push(format!(
                "PRODUCT: unlisted process-wide state: {file}:{lines:?} `{name}` — decide its \
                 disposition in ADR-026 P-1 and list it here"
            )),
            Some((count, _, _)) if *count != lines.len() => reds.push(format!(
                "PRODUCT: {file} has {} `{name}` (lines {lines:?}), the table lists {count} — \
                 a new one is unlisted",
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for ((file, name), (_, row, _)) in &listed {
        if !found.contains_key(&(file.clone(), name.clone())) {
            reds.push(format!(
                "PRODUCT (table): `{name}` in {file} ({row}) is listed but no longer there — \
                 take it off the table"
            ));
        }
    }
    for ((file, name), lines) in &found {
        if let Some((_, row, Some(pending))) = listed.get(&(file.clone(), name.clone())) {
            eprintln!("PENDING: {file}:{lines:?} `{name}` — ADR: {row} — {pending}");
        }
    }
    eprintln!(
        "{} process-wide items in {} files, each listed under its ADR-026 P-1 row",
        found.len(),
        files.len()
    );
    assert!(reds.is_empty(), "{}", reds.join("\n"));
}
