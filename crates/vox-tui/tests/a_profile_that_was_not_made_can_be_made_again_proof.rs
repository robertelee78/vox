//! V210-77 (#268) — **a profile whose making failed, or whose vault is gone, can be made again**,
//! through the shipped binary.
//!
//! `vox id` made a profile in two writes: the vault, then the store's public facts (the identity's
//! fingerprint and creation time). When the second failed, the vault was left beside a store with
//! no fingerprint: `vox id` then refused to make another ("identity already exists") and could not
//! open that one ("store is missing the identity fingerprint") — and the repair its comment
//! promised did not exist. And `vox id` in a profile whose vault was gone made the new identity
//! **over** the old store, full of what was sealed under the old identity: the new one then never
//! unlocked ("this node's trust keyring, pending consents or prekey ring will not open").
//!
//! The store is now written first and the vault last, so a failure leaves no identity; and a store
//! with no vault beside it is moved aside (kept, renamed `store.redb.orphaned-<secs>`), never
//! adopted; a failed attempt removes the store it made and puts back one it moved aside. Four
//! stagings, each a profile directory as a person could leave it:
//!
//! 1. **The store cannot be opened** where `vox id` makes it: a directory stands at `store.redb`.
//!    `vox id` must leave a usable identity within two tries — one that `vox id` opens again and a
//!    daemon unlocks.
//! 2. **A leftover store**: an identity made, then its `vault.cbor` removed. `vox id` must make a
//!    new identity that a daemon unlocks, whose ring `vox status --json` names, and the old store
//!    must be kept aside.
//! 3. **The vault cannot be written** (a directory stands at `vault.tmp`, so the store is written
//!    and the vault is not): `vox id` must name the identity file, not the store, and leave
//!    nothing behind — no store, nothing kept aside — in a fresh profile; over a leftover store it
//!    must put that store back where it was, byte for byte. Once the obstacle is gone, `vox id`
//!    succeeds.
//! 4. **The vault lands but its directory will not flush** (macOS): `vox id` runs under the
//!    test interposer with `VOX_INTERPOSE_FAIL_DIR_SYNC` naming the profile directory, so the
//!    vault's rename succeeds and the flush of the directory after it fails with `EIO`. The
//!    recorded calls must show exactly that (else PRODUCT (staging)). `vox id` must leave nothing —
//!    no vault, no store, nothing kept aside — or, over a leftover store, that store back in
//!    place byte for byte and no vault; and the next `vox id` must make an identity a daemon
//!    unlocks.
//!
//! Mutations that must turn it red: `vox id` opens whatever stands at `store.redb` (no move
//! aside: 1 and 2); a failed vault write reported as the store's (3); a failed attempt leaving its
//! store behind (3); a failed attempt leaving the vault it renamed into place (4).
//!
//! **On review only**: the order of the writes. No staging through the binary fails the store's
//! first write without something already at its path, which the move aside clears; the order is
//! what keeps any other failure there from leaving a vault behind.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[cfg(target_os = "macos")]
#[path = "support/syscalls.rs"]
mod syscalls;

#[path = "support/layout.rs"]
mod layout;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the profile proof";

/// A child killed and reaped by its own handle when dropped, never by a name pattern.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Profile {
    data: PathBuf,
    pass: PathBuf,
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Profile {
    fn new(tmp: &Path, name: &str) -> Self {
        let data = tmp.join(name);
        std::fs::create_dir_all(data.join("cfg"))
            .expect("APPARATUS: cannot make the profile directory");
        let pass = tmp.join(format!("{name}.pass"));
        std::fs::write(&pass, format!("{IDENTITY}\n"))
            .expect("APPARATUS: cannot write the passphrase file");
        Self { data, pass }
    }

    /// Where `vox` keeps the default node's files (`<data>/nodes/default/`).
    fn dir(&self) -> PathBuf {
        layout::node_dir(&self.data, layout::DEFAULT_NODE)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", self.data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM_PASSPHRASE")
            .env_remove("VOX_TEST_CLOCK_SKEW_MS");
        c
    }

    fn vox(&self, args: &[&str]) -> Out {
        let out = self
            .command(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox: {e}"));
        Out {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// `vox daemon`, and whether it came to answer `vox room list`, with what it said.
    fn daemon_answers(&self) -> (bool, String) {
        let err = self.data.join("daemon.err");
        let mut p = Proc(
            self.command(&[
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--passphrase-file",
                self.pass
                    .to_str()
                    .expect("APPARATUS: the passphrase path is not UTF-8"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&err)
                    .expect("APPARATUS: cannot create the daemon's stderr file"),
            ))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox daemon: {e}")),
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.vox(&["room", "list"]).ok {
                let s = self.vox(&["status", "--json"]);
                let prekeys = serde_json::from_str::<serde_json::Value>(&s.stdout)
                    .map(|v| v["prekeys"].clone())
                    .unwrap_or_default();
                return (true, format!("prekeys {prekeys}"));
            }
            if matches!(p.0.try_wait(), Ok(Some(_))) || Instant::now() >= deadline {
                return (false, std::fs::read_to_string(&err).unwrap_or_default());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Files beside the vault whose name starts `store.redb.orphaned-`.
    fn kept_aside(&self) -> usize {
        std::fs::read_dir(self.dir())
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("store.redb.orphaned-")
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// What is in the profile's directory, for a red that is about what was left there.
    fn listing(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir())
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn a_store_that_cannot_be_opened_leaves_no_half_made_identity() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let p = Profile::new(tmp.path(), "blocked");
    std::fs::create_dir_all(p.dir().join("store.redb"))
        .expect("APPARATUS: cannot stage a directory at store.redb");

    let mut said = Vec::new();
    let mut fingerprint = None;
    for attempt in 1..=2 {
        let o = p.vox(&["id"]);
        eprintln!(
            "[proof] vox id, try {attempt}: ok={} {}{}",
            o.ok,
            o.stdout.trim(),
            o.stderr.trim()
        );
        said.push(format!("{}{}", o.stdout, o.stderr));
        if o.ok {
            fingerprint = Some(o.stdout.trim().to_owned());
            break;
        }
    }
    let fingerprint = fingerprint.unwrap_or_else(|| {
        panic!("PRODUCT: `vox id` over a store it could not open left no usable identity in two tries: {said:?}")
    });
    let again = p.vox(&["id"]);
    eprintln!(
        "[proof] vox id again: ok={} {}{}",
        again.ok,
        again.stdout.trim(),
        again.stderr.trim()
    );
    assert!(
        again.ok && again.stdout.trim() == fingerprint,
        "PRODUCT: the identity `vox id` made must open again as itself ({fingerprint}): {}{}",
        again.stdout,
        again.stderr
    );
    let (answers, what) = p.daemon_answers();
    eprintln!(
        "[proof] its daemon answers: {answers} ({}); kept aside: {}",
        what.trim(),
        p.kept_aside()
    );
    assert!(
        answers,
        "PRODUCT: a daemon must unlock the identity `vox id` made: {what}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn an_identity_made_over_a_leftover_store_unlocks() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let p = Profile::new(tmp.path(), "leftover");
    let first = p.vox(&["id"]);
    assert!(
        first.ok,
        "PRODUCT (staging): the first vox id: {}{}",
        first.stdout, first.stderr
    );
    let (answers, what) = p.daemon_answers();
    assert!(
        answers,
        "PRODUCT (staging): the first identity's daemon never answered: {what}"
    );
    std::fs::remove_file(p.dir().join("vault.cbor"))
        .expect("APPARATUS: cannot remove the vault to stage a leftover store");

    let second = p.vox(&["id"]);
    eprintln!(
        "[proof] first {}; vault removed; vox id: ok={} {}{}",
        first.stdout.trim(),
        second.ok,
        second.stdout.trim(),
        second.stderr.trim()
    );
    assert!(
        second.ok && second.stdout.trim() != first.stdout.trim(),
        "PRODUCT: `vox id` with no vault must make a new identity: {}{}",
        second.stdout,
        second.stderr
    );
    let (answers, what) = p.daemon_answers();
    let aside = p.kept_aside();
    eprintln!(
        "[proof] the new identity's daemon answers: {answers} ({}); kept aside: {aside}",
        what.trim()
    );
    assert!(
        answers,
        "PRODUCT: a daemon must unlock the identity made where a vault was gone: {what}"
    );
    assert_eq!(
        aside,
        1,
        "PRODUCT: the old store must be kept aside once, not deleted; the profile holds {:?}",
        p.listing()
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn a_vault_that_cannot_be_written_is_named_and_leaves_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");

    // (a) a fresh profile: the store is written, then the vault cannot be.
    let p = Profile::new(tmp.path(), "novault");
    std::fs::create_dir_all(p.dir().join("vault.tmp"))
        .expect("APPARATUS: cannot stage a directory at vault.tmp");
    for attempt in 1..=2 {
        let o = p.vox(&["id"]);
        let store = p.dir().join("store.redb").exists();
        let aside = p.kept_aside();
        eprintln!(
            "[proof] vault unwritable, vox id try {attempt}: ok={} store left {store}, kept aside \
             {aside}: {}",
            o.ok,
            o.stderr.trim()
        );
        assert!(
            !o.ok,
            "PRODUCT (staging): vox id made an identity with vault.tmp a directory: {}",
            o.stdout.trim()
        );
        assert!(
            o.stderr.contains("identity file (vault.cbor)") && !o.stderr.contains("store"),
            "PRODUCT: a vault that cannot be written must be named as the identity file, not the store: {}",
            o.stderr.trim()
        );
        assert!(
            !store && aside == 0,
            "PRODUCT: a failed `vox id` must leave nothing behind (store left {store}, kept aside \
             {aside}); it said: {}; the profile holds {:?}",
            o.stderr.trim(),
            p.listing()
        );
    }
    std::fs::remove_dir(p.dir().join("vault.tmp"))
        .expect("APPARATUS: cannot remove the staged vault.tmp");
    let o = p.vox(&["id"]);
    let aside = p.kept_aside();
    eprintln!(
        "[proof] obstacle removed: vox id ok={} {}; kept aside {aside}",
        o.ok,
        o.stdout.trim()
    );
    assert!(
        o.ok && aside == 0,
        "PRODUCT: the retry must make the identity and keep nothing aside (kept aside {aside}); \
         it said: {}{}",
        o.stdout.trim(),
        o.stderr.trim()
    );

    // (b) a leftover store: a failed attempt puts it back where it was, untouched.
    let q = Profile::new(tmp.path(), "leftover-then-fail");
    let first = q.vox(&["id"]);
    assert!(
        first.ok,
        "PRODUCT (staging): the first vox id: {}",
        first.stderr
    );
    std::fs::remove_file(q.dir().join("vault.cbor"))
        .expect("APPARATUS: cannot remove the vault to stage a leftover store");
    let before = std::fs::read(q.dir().join("store.redb"))
        .expect("APPARATUS: cannot read the leftover store");
    std::fs::create_dir_all(q.dir().join("vault.tmp"))
        .expect("APPARATUS: cannot stage a directory at vault.tmp");
    let o = q.vox(&["id"]);
    let back = std::fs::read(q.dir().join("store.redb")).ok();
    let aside = q.kept_aside();
    eprintln!(
        "[proof] leftover store, vault unwritable: ok={}; the leftover back in place: {}; kept \
         aside {aside}",
        o.ok,
        back.as_deref() == Some(&before[..])
    );
    assert!(
        !o.ok && back.as_deref() == Some(&before[..]) && aside == 0,
        "PRODUCT: a failed `vox id` must put the leftover store back where it was, byte for byte \
         (ok={}, kept aside {aside}); it said: {}; the profile holds {:?}",
        o.ok,
        o.stderr.trim(),
        q.listing()
    );
    std::fs::remove_dir(q.dir().join("vault.tmp"))
        .expect("APPARATUS: cannot remove the staged vault.tmp");
    let o = q.vox(&["id"]);
    let aside = q.kept_aside();
    eprintln!(
        "[proof] obstacle removed: vox id ok={}; kept aside {aside}",
        o.ok
    );
    assert!(
        o.ok && aside == 1,
        "PRODUCT: the retry must make the identity and keep the leftover store aside, once (kept \
         aside {aside}); it said: {}; the profile holds {:?}",
        o.stderr.trim(),
        q.listing()
    );
}

/// **A temporary file an earlier attempt left does not stand in the way** (#399): a failed or
/// killed `vox id` can leave `vault.tmp` behind, and the next `vox id` must make the identity
/// anyway — with the file a crash leaves, and with one of another mode. Mutant: the vault write
/// not clearing its old temporary file.
#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn a_temporary_file_left_by_an_earlier_attempt_does_not_block_the_next() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let p = Profile::new(tmp.path(), "leftover-tmp");
    std::fs::create_dir_all(p.dir()).expect("APPARATUS: cannot make the node directory");
    let left = p.dir().join("vault.tmp");
    std::fs::write(&left, b"half of an earlier vault").expect("APPARATUS: cannot stage vault.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&left, std::fs::Permissions::from_mode(0o444))
            .expect("APPARATUS: cannot set vault.tmp's mode");
    }
    let o = p.vox(&["id"]);
    eprintln!(
        "[proof] with a leftover vault.tmp, vox id ok={}: {}{}",
        o.ok,
        o.stdout.trim(),
        o.stderr.trim()
    );
    assert!(
        o.ok && o.stdout.trim().len() == 52,
        "PRODUCT: a vault.tmp left by an earlier attempt kept `vox id` from making the identity: {}",
        o.stderr.trim()
    );
    assert!(
        !left.exists() && p.dir().join("vault.cbor").exists(),
        "PRODUCT: after `vox id` the leftover vault.tmp is still there or no vault was written; \
         the profile holds {:?}",
        p.listing()
    );
}

/// `vox id` under the test interposer, with every flush of `dir` failing with `EIO`. Returns
/// success, stderr, and whether the vault's rename landed and a flush of `dir` failed after it.
#[cfg(target_os = "macos")]
fn id_with_the_directory_unflushable(p: &Profile) -> (bool, String, bool) {
    let dir = std::fs::canonicalize(p.dir()).expect("APPARATUS: no profile directory");
    let log = p.data.join(format!("interpose-{}.tsv", std::process::id()));
    let out = p
        .command(&["id"])
        .env("DYLD_INSERT_LIBRARIES", syscalls::interposer())
        .env("VOX_INTERPOSE_LOG", &log)
        .env("VOX_INTERPOSE_FAIL_DIR_SYNC", &dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox id under the interposer: {e}"));
    let events = syscalls::parse(&std::fs::read_to_string(&log).unwrap_or_default());
    let _ = std::fs::remove_file(&log);
    syscalls::assert_the_recorder_saw_vox(&events, "`vox id` with the directory unflushable");
    let vault = dir.join("vault.cbor");
    let landed = events.iter().position(|e| {
        matches!(&e.call, syscalls::Call::Rename { to, .. } if syscalls::norm(to) == vault)
            && e.ret == 0
    });
    let staged = landed.is_some_and(|at| {
        events[at..].iter().any(|e| {
            matches!(&e.call, syscalls::Call::Sync { path, .. } if *path == dir) && e.errno == 5
        })
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        staged,
    )
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "real binaries, production Argon2id and the test interposer; the release gate runs it"]
fn a_vault_whose_directory_will_not_flush_leaves_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");

    // (a) a fresh profile.
    let p = Profile::new(tmp.path(), "noflush");
    std::fs::create_dir_all(p.dir()).expect("APPARATUS: cannot make the profile directory");
    let (ok, said, staged) = id_with_the_directory_unflushable(&p);
    let (vault, store, aside) = (
        p.dir().join("vault.cbor").exists(),
        p.dir().join("store.redb").exists(),
        p.kept_aside(),
    );
    eprintln!(
        "[proof] vault renamed, directory flush EIO: staged {staged}; vox id ok={ok}; vault left \
         {vault}, store left {store}, kept aside {aside}: {}",
        said.trim()
    );
    assert!(
        staged,
        "PRODUCT (staging): the vault's rename did not land before a failed flush of the directory; \
         vox said: {}",
        said.trim()
    );
    assert!(
        !ok,
        "PRODUCT: vox id reported success though the flush of its directory failed after the \
         vault landed: {}",
        said.trim()
    );
    assert!(
        !vault && !store && aside == 0,
        "PRODUCT: a failed `vox id` must leave nothing behind, the vault included (vault left \
         {vault}, store left {store}, kept aside {aside}); it said: {}",
        said.trim()
    );
    let o = p.vox(&["id"]);
    let again = p.vox(&["id"]);
    let (answers, what) = p.daemon_answers();
    eprintln!(
        "[proof] then vox id ok={} {}; again ok={}; its daemon answers: {answers}",
        o.ok,
        o.stdout.trim(),
        again.ok
    );
    assert!(
        o.ok && again.ok && again.stdout.trim() == o.stdout.trim() && answers,
        "PRODUCT: the next `vox id` must make an identity that opens again and a daemon unlocks: {}{} {what}",
        o.stderr,
        again.stderr
    );

    // (b) over a leftover store.
    let q = Profile::new(tmp.path(), "noflush-leftover");
    let first = q.vox(&["id"]);
    assert!(
        first.ok,
        "PRODUCT (staging): the first vox id: {}",
        first.stderr
    );
    std::fs::remove_file(q.dir().join("vault.cbor"))
        .expect("APPARATUS: cannot remove the vault to stage a leftover store");
    let before = std::fs::read(q.dir().join("store.redb"))
        .expect("APPARATUS: cannot read the leftover store");
    let (ok, said, staged) = id_with_the_directory_unflushable(&q);
    let vault = q.dir().join("vault.cbor").exists();
    let back = std::fs::read(q.dir().join("store.redb")).ok();
    let aside = q.kept_aside();
    eprintln!(
        "[proof] leftover store, directory flush EIO: staged {staged}; vox id ok={ok}; vault left \
         {vault}; the leftover back in place: {}; kept aside {aside}: {}",
        back.as_deref() == Some(&before[..]),
        said.trim()
    );
    assert!(
        staged,
        "PRODUCT (staging): the leftover staging did not fail after the vault's rename; vox said: {}",
        said.trim()
    );
    assert!(
        !ok,
        "PRODUCT: vox id over a leftover store reported success though the flush of its \
         directory failed after the vault landed: {}",
        said.trim()
    );
    assert!(
        !vault && back.as_deref() == Some(&before[..]) && aside == 0,
        "PRODUCT: a failed `vox id` over a leftover store must leave no vault and that store back \
         in place (vault left {vault}, kept aside {aside}); it said: {}",
        said.trim()
    );
    let o = q.vox(&["id"]);
    let (answers, what) = q.daemon_answers();
    eprintln!(
        "[proof] then vox id ok={}; its daemon answers: {answers}; kept aside {}",
        o.ok,
        q.kept_aside()
    );
    assert!(
        o.ok && answers && q.kept_aside() == 1,
        "PRODUCT: the next `vox id` must make an identity a daemon unlocks, the leftover kept \
         aside once: \
         {} {what}",
        o.stderr
    );
}
