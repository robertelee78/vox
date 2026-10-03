//! V210-100 (#296) — **two vox processes unlocking one v0.2.9 profile at once lose none of its
//! rows, and a refused one names the cause**, through the shipped binary.
//!
//! A profile written by v0.2.9 has a version-1 vault, and the first unlock by this build migrates
//! it (V210-40, #214): it re-seals the node-wide blobs, rewrites the store into a new file and
//! renames that over `store.redb`, then rewrites the vault as version 2. redb's lock is on the
//! file, so it lapses between releasing the old file and the rename. A second vox unlocking the
//! same profile at that moment opened the old file, migrated it again, and renamed its copy over
//! the first one's: every row the first had written since its own rename was gone, although it
//! had exited 0. The whole migration now runs under the profile directory's lock (V210-91's), and
//! whoever waits for it reads the vault again, so a profile migrated meanwhile is not migrated
//! twice. An unlock that meets another vox holding the store said "an internal error — a bug in
//! vox"; it now says another vox holds the profile.
//!
//! Staging: the **released v0.2.9 binary** (checked against its published SHA-256) writes a
//! profile with a trusted member and a shared room with a post in it. Each trial unlocks a fresh
//! copy of it from two processes at once, each running `vox trust add` for a different identity —
//! a write made after the unlock, which is what the lost window took:
//!
//! 1. **Natural.** [`TRIALS`] copies; the second process starts a little later on each (0 to
//!    1.5 s), so between them the starts cover the first one's open, unlock and migration.
//! 2. **Staged.** The first process waits [`REPLACE_PAUSE_MS`] in the window itself (the store
//!    released, the new file not yet renamed: `VOX_TEST_REPLACE_PAUSE_MS`); the second starts once
//!    it says it is there, and if it migrates too, waits [`REWRITE_DELAY_MS`] before its own
//!    rewrite (`VOX_TEST_REWRITE_DELAY_MS`), so the first one finishes in between. Both knobs are
//!    proof-only and inert when unset.
//!
//! Asserted, per trial, after both have exited:
//! - **every `trust add` that exited 0 is in `vox trust list`**, and so is the member v0.2.9
//!   trusted;
//! - every row key of v0.2.9's store (its room's segments and key wraps, and its meta rows) is
//!   still in the store;
//! - the vault is version 2, and no `store.redb.rewrite` or `*.orphaned-*` is left;
//! - **the profile was migrated exactly once**: every process runs with
//!   `VOX_TEST_REWRITE_DELAY_MS` (0 when nothing is staged), which makes each one that migrates
//!   say so, and the trial counts those lines;
//! - every run that failed names another vox holding the profile — never an internal error;
//! - **in the natural arm, none of the 20 two-at-once starts refuses either process**: every vox
//!   takes the profile's lock before it opens the store, so the second waits for the first;
//! - the same for a profile this build made (no migration): 20 pairs of `vox trust add` started at
//!   the same instant, neither refused, both names listed.
//!
//! A lone unlock of a copy is the control: it must pass the same row checks, or nothing here
//! would mean anything.
//!
//! Mutations that must turn it red: the store opened before the profile's lock is taken, or the
//! lock released before the store is closed: of two started together, one is refused. The profile lock not held across the migration: in the staged
//! arm the second process migrates the old file and renames it over the first one's, and the
//! first one's `trust add` is gone (or the profile is migrated twice).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/previous_release.rs"]
mod previous_release;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use vox_core::atrest::vault::IdentityVault;
use vox_core::hash::Digest32;

use previous_release::{previous_release, PREVIOUS};
use world::{args, node_dir, VoxProc, DEFAULT_NODE, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(90);
/// Copies unlocked twice at once in the natural arm (fewer in a debug build, whose Argon2id
/// takes many times as long).
const TRIALS: usize = if cfg!(debug_assertions) { 6 } else { 20 };
/// Staged-arm trials.
const STAGED: usize = 2;
/// How long the first process waits with the store released and not yet replaced.
const REPLACE_PAUSE_MS: &str = "8000";
/// How long a second process that migrates too waits before its own rewrite.
const REWRITE_DELAY_MS: &str = "12000";
/// What a refusal says when another vox holds the profile (the CLI's words, and the fault's).
const NAMED: [&str; 3] = [
    "a vox is already running for this profile",
    "another vox is still using this profile",
    "run this again once that one is done",
];
/// What the knobs print when their moment is reached.
const AT_REPLACE: &str = "the store is released, not yet replaced";
const AT_REWRITE: &str = "about to rewrite the store";

// ---- driving a `vox` binary (this build's, or the previous release's) ------------------------

fn vox_with(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    if let Some(s) = stdin {
        child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdio handle")
            .write_all(s.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ok(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> String {
    let (good, out, err) = vox_with(exe, data, argv, stdin);
    // This build failing a step is the product's; the previous release failing one is not.
    let side = if exe == Path::new(VOX) {
        "PRODUCT (staging)"
    } else {
        "APPARATUS, CANNOT MEASURE: the previous release"
    };
    assert!(good, "{side}: vox {argv:?} failed: {out}{err}");
    out
}

fn anchor(exe: &Path, data: &Path) -> (VoxProc, String) {
    let mut p = VoxProc::spawn_exe(
        exe,
        "anchor",
        data,
        &args(&["node", "--listen", "127.0.0.1:0"]),
        &[],
    );
    let spec = p
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    (p, spec)
}

fn daemon(exe: &Path, name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn_exe(
        exe,
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
        ]),
        &[],
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_with(exe, data, &["room", "list"], None).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
}

/// Create a room on `host`'s daemon, have `guest` join it, and return the room's id.
fn shared_room(exe: &Path, host: &Path, guest: &Path, name: &str) -> String {
    // The room passphrase goes on stdin. This build reads it there only when told
    // (`--passphrase-file -`, v0.2.10); the previous release has no such flag and reads stdin
    // unasked, so it is given the argv it accepts.
    let from_stdin: &[&str] = if exe == Path::new(VOX) {
        &["--passphrase-file", "-"]
    } else {
        &[]
    };
    let create = [&["room", "create"][..], from_stdin, &["--name", name]].concat();
    ok(exe, host, &create, Some("room pass"));
    let list = ok(exe, host, &["room", "list"], None);
    let room = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): room not listed: {list}"))
        .to_owned();
    let link = ok(exe, host, &["room", "invite", &room], None);
    let join = [
        &["room", "join"][..],
        from_stdin,
        &[link.trim(), "--name", name],
    ]
    .concat();
    ok(exe, guest, &join, Some("room pass"));
    room
}

// ---- the profile on disk ---------------------------------------------------------------------

/// The default node's directory as this build keeps it, `<data>/nodes/default/` (ADR-026 §7).
fn profile_dir(data: &Path) -> PathBuf {
    node_dir(data, DEFAULT_NODE)
}

/// The default profile's directory as v0.2.9 left it, `<data>/default/`, which this build's first
/// run moves to [`profile_dir`] (ADR-026 F-3): what v0.2.9 wrote is read here, what a trial left
/// there — read here, a trial's profile would be missing, not clean.
fn old_profile_dir(data: &Path) -> PathBuf {
    data.join(DEFAULT_NODE)
}

/// Copy a stopped profile's data directory (its files; a daemon's leftover socket is not one).
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("APPARATUS: create a staging directory");
    for e in std::fs::read_dir(from)
        .expect("APPARATUS: list a directory")
        .filter_map(Result::ok)
    {
        let ty = e
            .file_type()
            .expect("APPARATUS: read a staging file's type");
        let dest = to.join(e.file_name());
        if ty.is_dir() {
            copy_tree(&e.path(), &dest);
        } else if ty.is_file() {
            std::fs::copy(e.path(), &dest).expect("APPARATUS: copy the v0.2.9 profile");
        }
    }
}

type SegmentKey = (Digest32, u8, u64);
const SEGMENTS: TableDefinition<SegmentKey, &[u8]> = TableDefinition::new("segments");
const SEK_WRAPS: TableDefinition<Digest32, &[u8]> = TableDefinition::new("sek_wraps");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Every row key in the store of the stopped profile at `profile` under data root `data`, named by
/// table. Read from a copy, so a store that redb would repair on open is not changed by reading it.
fn row_keys(data: &Path, profile: &Path) -> BTreeSet<String> {
    let copy = data.with_extension("rows.redb");
    std::fs::copy(profile.join("store.redb"), &copy)
        .expect("PRODUCT (staging): the profile has no store.redb to read");
    let db = redb::Database::open(&copy).expect("APPARATUS: open a copy of the stopped store");
    let r = db
        .begin_read()
        .expect("PRODUCT: vox's stopped store cannot be read");
    let mut keys = BTreeSet::new();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    if let Ok(t) = r.open_table(SEGMENTS) {
        for item in t
            .iter()
            .expect("PRODUCT: a table of vox's stopped store cannot be read")
        {
            let (k, _) = item.expect("PRODUCT: a row of vox's stopped store cannot be read");
            let (c, kind, id) = k.value();
            keys.insert(format!("segments/{}/{kind}/{id}", hex(&c)));
        }
    }
    if let Ok(t) = r.open_table(SEK_WRAPS) {
        for item in t
            .iter()
            .expect("PRODUCT: a table of vox's stopped store cannot be read")
        {
            let (k, _) = item.expect("PRODUCT: a row of vox's stopped store cannot be read");
            keys.insert(format!("sek_wraps/{}", hex(&k.value())));
        }
    }
    if let Ok(t) = r.open_table(META) {
        for item in t
            .iter()
            .expect("PRODUCT: a table of vox's stopped store cannot be read")
        {
            let (k, _) = item.expect("PRODUCT: a row of vox's stopped store cannot be read");
            keys.insert(format!("meta/{}", k.value()));
        }
    }
    keys
}

fn vault_version(profile: &Path) -> u64 {
    let bytes = std::fs::read(profile.join("vault.cbor"))
        .expect("PRODUCT (staging): the profile has no vault.cbor");
    IdentityVault::from_canonical_slice(&bytes)
        .expect("PRODUCT: the vault vox wrote does not parse")
        .version
}

/// Files a migration must not leave behind: its rewrite's new file, or a store moved aside.
fn leftovers(data: &Path) -> Vec<String> {
    std::fs::read_dir(profile_dir(data))
        .expect("APPARATUS: list a directory")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".rewrite") || n.contains("orphaned"))
        .collect()
}

/// The petnames `vox trust list` shows.
fn trusted_names(data: &Path) -> BTreeSet<String> {
    let out = ok(Path::new(VOX), data, &["trust", "list"], None);
    out.lines()
        .filter_map(|l| l.split_once("  ").map(|(_, n)| n.trim().to_owned()))
        .collect()
}

// ---- one trial -------------------------------------------------------------------------------

/// What one process of a trial came to.
struct Ran {
    name: &'static str,
    exited_ok: bool,
    said: String,
}

impl Ran {
    fn named(&self) -> bool {
        NAMED.iter().any(|n| self.said.contains(n))
    }
}

/// Start `vox trust add` on `data`. Every process gets `VOX_TEST_REWRITE_DELAY_MS` (0 unless
/// `env` sets it), so each one that migrates says so ([`AT_REWRITE`]) and a trial can count its
/// migrations.
fn trust_add(data: &Path, who: &'static str, fp: &str, env: &[(&str, &str)]) -> VoxProc {
    let mut env = env.to_vec();
    if !env.iter().any(|(k, _)| *k == "VOX_TEST_REWRITE_DELAY_MS") {
        env.push(("VOX_TEST_REWRITE_DELAY_MS", "0"));
    }
    VoxProc::spawn_env(
        &format!("trust add {who}"),
        data,
        &args(&["trust", "add", fp, "--name", who]),
        &env,
    )
}

fn finish(mut p: VoxProc, name: &'static str) -> Ran {
    let status = p.child.wait().expect("APPARATUS: wait for vox");
    // The reader threads end when the pipes close; give them a moment to hand over the rest.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut said = String::new();
    loop {
        match p.lines.recv_timeout(Duration::from_millis(200)) {
            Ok(l) => {
                said.push_str(&l);
                said.push('\n');
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if Instant::now() > deadline => break,
            Err(_) => {}
        }
    }
    let said = format!("{}{}", p.seen.join("\n"), said);
    Ran {
        name,
        exited_ok: status.success(),
        said,
    }
}

#[derive(Default)]
struct Tally {
    trials: usize,
    both_ok: usize,
    one_ok: usize,
    none_ok: usize,
    refused_named: usize,
    /// Every `trust add` that exited 0 and whose name `trust list` no longer shows.
    lost_adds: Vec<String>,
    /// v0.2.9 rows gone from the store.
    lost_rows: Vec<String>,
    unnamed: Vec<String>,
    not_v2: usize,
    left: Vec<String>,
    dave_gone: usize,
    second_migrated: usize,
    /// Trials in which the profile was not migrated exactly once.
    not_once: Vec<String>,
}

impl Tally {
    fn judge(&mut self, label: &str, data: &Path, template: &BTreeSet<String>, runs: &[Ran]) {
        self.trials += 1;
        let oks = runs.iter().filter(|r| r.exited_ok).count();
        match oks {
            2 => self.both_ok += 1,
            1 => self.one_ok += 1,
            _ => self.none_ok += 1,
        }
        for r in runs.iter().filter(|r| !r.exited_ok) {
            if r.named() {
                self.refused_named += 1;
            } else {
                self.unnamed
                    .push(format!("{label} {}: {}", r.name, r.said.trim()));
            }
        }
        let names = trusted_names(data);
        for r in runs.iter().filter(|r| r.exited_ok) {
            if !names.contains(r.name) {
                self.lost_adds.push(format!(
                    "{label}: `trust add {}` exited 0, and `trust list` shows {names:?}",
                    r.name
                ));
            }
        }
        if !names.contains("dave") {
            self.dave_gone += 1;
        }
        let now = row_keys(data, &profile_dir(data));
        for k in template.difference(&now) {
            self.lost_rows.push(format!("{label}: {k}"));
        }
        if oks > 0 && vault_version(&profile_dir(data)) != 2 {
            self.not_v2 += 1;
        }
        for f in leftovers(data) {
            self.left.push(format!("{label}: {f}"));
        }
        let migrations = runs.iter().filter(|r| r.said.contains(AT_REWRITE)).count();
        if migrations != 1 {
            self.not_once
                .push(format!("{label}: migrated {migrations} times"));
        }
        println!(
            "[trial] {label}: exited 0 {oks}/{}; migrations {migrations}; trust list {names:?}; rows {} of v0.2.9's {} kept; vault v{}",
            runs.len(),
            template.intersection(&now).count(),
            template.len(),
            vault_version(&profile_dir(data))
        );
    }
}

#[test]
#[ignore = "real vox processes with production Argon2id, and the v0.2.9 release; CI runs it in release"]
fn two_unlocks_of_one_v1_profile_lose_no_rows() {
    test_knobs::require(&["VOX_TEST_REPLACE_PAUSE_MS", "VOX_TEST_REWRITE_DELAY_MS"]);
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        2400
    } else {
        600
    }));
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write a staging file");
    let new = PathBuf::from(VOX);

    // ---- a profile written by v0.2.9: a trusted member, and a room with a post ---------------
    let old = previous_release();
    let (carol, dave) = (dir("carol"), dir("dave"));
    let dave_fp = ok(&old, &dave, &["id"], None).trim().to_owned();
    ok(&old, &carol, &["id"], None);
    ok(
        &old,
        &carol,
        &["trust", "add", &dave_fp, "--name", "dave"],
        None,
    );
    {
        let (_node, spec) = anchor(&old, &dir("old-anchor"));
        let _carol_d = daemon(&old, "carol (v0.2.9)", &carol, &spec, &idpass);
        let _dave_d = daemon(&old, "dave (v0.2.9)", &dave, &spec, &idpass);
        let room = shared_room(&old, &carol, &dave, "carried");
        for n in 0..5 {
            ok(
                &old,
                &carol,
                &["room", "post", &room, &format!("written by v0.2.9, {n}")],
                None,
            );
        }
    }
    // The daemons were stopped by SIGKILL, which leaves a store redb must repair on its next
    // open. A person's profile is closed cleanly far more often; one more v0.2.9 command opens
    // it, repairs it, and closes it cleanly, so the trials start from the ordinary case.
    ok(&old, &carol, &["trust", "list"], None);
    assert_eq!(
        vault_version(&old_profile_dir(&carol)),
        1,
        "APPARATUS, CANNOT MEASURE: the previous release {PREVIOUS} did not write a version-1 \
         vault"
    );
    let template = row_keys(&carol, &old_profile_dir(&carol));
    let room_rows = template
        .iter()
        .filter(|k| k.starts_with("segments/") || k.starts_with("sek_wraps/"))
        .count();
    println!(
        "[proof] {PREVIOUS} profile: vault v1, {} row keys ({room_rows} segment and key-wrap rows)",
        template.len()
    );
    assert!(
        room_rows >= 3,
        "APPARATUS, CANNOT MEASURE: the previous release {PREVIOUS}'s store holds only {room_rows} room rows: {template:?}"
    );
    // The identities the trials trust: made by this build, once.
    let (erin, frank) = (dir("erin"), dir("frank"));
    let x_fp = ok(&new, &erin, &["id"], None).trim().to_owned();
    let y_fp = ok(&new, &frank, &["id"], None).trim().to_owned();

    // ---- the control: one unlock alone ----------------------------------------------------
    let control = dir("control");
    copy_tree(&carol, &control);
    let mut ctl = Tally::default();
    let alone = finish(trust_add(&control, "x", &x_fp, &[]), "x");
    ctl.judge("control", &control, &template, &[alone]);
    assert!(
        ctl.both_ok + ctl.one_ok == 1
            && ctl.lost_adds.is_empty()
            && ctl.lost_rows.is_empty()
            && ctl.not_v2 == 0
            && ctl.left.is_empty()
            && ctl.dave_gone == 0,
        "PRODUCT: one unlock of a {PREVIOUS} profile, with nothing racing it, already loses \
         something: adds lost {:?}, rows lost {:?}, not v2 {}, left {:?}, dave gone {}, \
         unnamed {:?}",
        ctl.lost_adds,
        ctl.lost_rows,
        ctl.not_v2,
        ctl.left,
        ctl.dave_gone,
        ctl.unnamed
    );
    assert!(
        ctl.not_once.is_empty(),
        "APPARATUS, CANNOT MEASURE (test knob): the lone unlock's migration was not counted by \
         its {AT_REWRITE:?} notice, so no trial's count means anything: {:?}",
        ctl.not_once
    );

    // ---- 1. natural: two at once, the second a little later each time --------------------
    let mut nat = Tally::default();
    for i in 0..TRIALS {
        let data = dir(&format!("natural-{i}"));
        copy_tree(&carol, &data);
        let a = trust_add(&data, "x", &x_fp, &[]);
        std::thread::sleep(Duration::from_millis(75 * i as u64));
        let b = trust_add(&data, "y", &y_fp, &[]);
        let runs = [finish(a, "x"), finish(b, "y")];
        nat.judge(&format!("natural {i}"), &data, &template, &runs);
    }

    // ---- 2. staged: the second arrives while the first's store is released ----------------
    let mut staged = Tally::default();
    let mut reached = 0;
    for i in 0..STAGED {
        let data = dir(&format!("staged-{i}"));
        copy_tree(&carol, &data);
        let mut a = trust_add(
            &data,
            "x",
            &x_fp,
            &[("VOX_TEST_REPLACE_PAUSE_MS", REPLACE_PAUSE_MS)],
        );
        a.expect_within(Duration::from_secs(300), "the store released", |l| {
            l.contains(AT_REPLACE)
        });
        reached += 1;
        let b = trust_add(
            &data,
            "y",
            &y_fp,
            &[("VOX_TEST_REWRITE_DELAY_MS", REWRITE_DELAY_MS)],
        );
        let runs = [finish(a, "x"), finish(b, "y")];
        if runs[1].said.contains(AT_REWRITE) {
            staged.second_migrated += 1;
        }
        staged.judge(&format!("staged {i}"), &data, &template, &runs);
    }

    // ---- 3. this build's own profile: two `trust add`s started at the same instant -------------
    // Not a migration: the claim that neither of two commands started together is refused holds
    // for every profile, and verification of c5 found it broken on a fresh one too.
    let own = dir("own-template");
    ok(&new, &own, &["id"], None);
    let (mut own_both, mut own_refused, mut own_lost) = (0, Vec::new(), Vec::new());
    for i in 0..TRIALS {
        let data = dir(&format!("own-{i}"));
        copy_tree(&own, &data);
        let a = trust_add(&data, "x", &x_fp, &[]);
        let b = trust_add(&data, "y", &y_fp, &[]);
        let runs = [finish(a, "x"), finish(b, "y")];
        for r in runs.iter().filter(|r| !r.exited_ok) {
            own_refused.push(format!("own {i} `trust add {}`: {}", r.name, r.said.trim()));
        }
        let names = trusted_names(&data);
        for r in runs.iter().filter(|r| r.exited_ok) {
            if !names.contains(r.name) {
                own_lost.push(format!(
                    "own {i}: `trust add {}` exited 0, and `trust list` shows {names:?}",
                    r.name
                ));
            }
        }
        if runs.iter().all(|r| r.exited_ok) {
            own_both += 1;
        }
    }
    println!(
        "[proof] own profile: {TRIALS} trials x 2 started together: both exited 0 {own_both}; \
         refused {}; `trust add`s that exited 0 and are gone {}",
        own_refused.len(),
        own_lost.len()
    );

    for (arm, t) in [("natural", &nat), ("staged", &staged)] {
        println!(
            "[proof] {arm}: {} trials x 2: both exited 0 {}, one {}, none {}; refused naming \
             another vox {}; `trust add`s that exited 0 and are gone {}; v0.2.9 rows gone {}; \
             failed without naming the cause {}; vault not v2 {}; files left {}; dave gone {}; \
             second process migrated too {}; trials not migrated exactly once {}",
            t.trials,
            t.both_ok,
            t.one_ok,
            t.none_ok,
            t.refused_named,
            t.lost_adds.len(),
            t.lost_rows.len(),
            t.unnamed.len(),
            t.not_v2,
            t.left.len(),
            t.dave_gone,
            t.second_migrated,
            t.not_once.len()
        );
    }
    println!("[proof] staged: the first process reached the released store in {reached}/{STAGED}");

    // **Two started together both run** (V210-100): each takes the profile's lock before it
    // opens the store, so the second waits for the first instead of being refused.
    assert!(
        nat.refused_named == 0 && nat.one_ok == 0,
        "PRODUCT: of {} two-at-once starts, {} ended with one of the two refused (\"a vox is \
         already running for this profile\"), {} refusals in all — two vox started together \
         must both run, the second after the first",
        nat.trials,
        nat.one_ok,
        nat.refused_named
    );
    assert!(
        own_refused.is_empty(),
        "PRODUCT: of {TRIALS} pairs of `vox trust add` started together on this build's own \
         profile, {} commands were refused — two vox started together must both run, the second \
         after the first: {:#?}",
        own_refused.len(),
        own_refused
    );
    assert!(
        own_lost.is_empty(),
        "PRODUCT: a `vox trust add` exited 0 and its row is gone: {own_lost:#?}"
    );
    for t in [&nat, &staged] {
        assert!(
            t.lost_adds.is_empty(),
            "PRODUCT: a `vox trust add` exited 0 and its row is gone: {:#?}",
            t.lost_adds
        );
        assert!(
            t.lost_rows.is_empty(),
            "PRODUCT: rows v0.2.9 wrote are gone from the store: {:#?}",
            t.lost_rows
        );
        assert_eq!(t.dave_gone, 0, "PRODUCT: the member v0.2.9 trusted is gone");
        assert!(
            t.unnamed.is_empty(),
            "PRODUCT: a refused unlock did not name another vox holding the profile: {:#?}",
            t.unnamed
        );
        assert_eq!(
            t.not_v2, 0,
            "PRODUCT: a profile that was unlocked is still a v1 vault"
        );
        assert!(
            t.left.is_empty(),
            "PRODUCT: files left behind: {:?}",
            t.left
        );
        assert_eq!(
            t.none_ok, 0,
            "PRODUCT: both unlocks were refused, so the profile could be opened by neither"
        );
        assert!(
            t.not_once.is_empty(),
            "PRODUCT: a profile was not migrated exactly once — a vox that waited for the lock migrated \
             it again: {:#?}",
            t.not_once
        );
    }
}
