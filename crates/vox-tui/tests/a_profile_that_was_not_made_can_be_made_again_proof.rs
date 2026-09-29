//! V210-77 (#268) — **a profile whose making failed, or whose vault is gone, can be made again**,
//! through the shipped binary.
//!
//! `vox id` made a profile in two writes: the vault, then the store's public facts (the identity's
//! fingerprint and creation time). When the second failed, the vault was left beside a store with
//! no fingerprint: `vox id` then refused to make another ("identity already exists") and could not
//! open that one ("store is missing the identity fingerprint") — and the repair its comment
//! promised did not exist. And `vox id` in a profile whose vault was gone made the new identity
//! **over** the old store, full of what was sealed under the old identity: the new one then never
//! unlocked ("this profile's trust keyring, pending consents or prekey ring will not open").
//!
//! The store is now written first and the vault last, so a failure leaves no identity; and a store
//! with no vault beside it is moved aside (kept, renamed `store.redb.orphaned-<secs>`), never
//! adopted; a failed attempt removes the store it made and puts back one it moved aside. Three
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
//!
//! Mutations that must turn it red: `vox id` opens whatever stands at `store.redb` (no move
//! aside: 1 and 2); a failed vault write reported as the store's (3); a failed attempt leaving its
//! store behind (3).
//!
//! **On review only**: the order of the writes. No staging through the binary fails the store's
//! first write without something already at its path, which the move aside clears; the order is
//! what keeps any other failure there from leaving a vault behind.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
        std::fs::create_dir_all(data.join("cfg")).unwrap();
        let pass = tmp.join(format!("{name}.pass"));
        std::fs::write(&pass, format!("{IDENTITY}\n")).unwrap();
        Self { data, pass }
    }

    /// Where `vox` keeps the default profile's files.
    fn dir(&self) -> PathBuf {
        self.data.join("default")
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
            .expect("run vox");
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
                self.pass.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
            .spawn()
            .expect("spawn vox daemon"),
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
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn a_store_that_cannot_be_opened_leaves_no_half_made_identity() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let p = Profile::new(tmp.path(), "blocked");
    std::fs::create_dir_all(p.dir().join("store.redb")).unwrap();

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
        panic!("`vox id` over a store it could not open left no usable identity in two tries: {said:?}")
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
        "the identity `vox id` made must open again as itself ({fingerprint}): {}{}",
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
        "a daemon must unlock the identity `vox id` made: {what}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn an_identity_made_over_a_leftover_store_unlocks() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let p = Profile::new(tmp.path(), "leftover");
    let first = p.vox(&["id"]);
    assert!(
        first.ok,
        "CANNOT MEASURE: the first vox id: {}{}",
        first.stdout, first.stderr
    );
    let (answers, what) = p.daemon_answers();
    assert!(
        answers,
        "CANNOT MEASURE: the first identity's daemon never answered: {what}"
    );
    std::fs::remove_file(p.dir().join("vault.cbor")).unwrap();

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
        "`vox id` with no vault must make a new identity: {}{}",
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
        "a daemon must unlock the identity made where a vault was gone: {what}"
    );
    assert_eq!(aside, 1, "the old store must be kept aside, not deleted");
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn a_vault_that_cannot_be_written_is_named_and_leaves_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();

    // (a) a fresh profile: the store is written, then the vault cannot be.
    let p = Profile::new(tmp.path(), "novault");
    std::fs::create_dir_all(p.dir().join("vault.tmp")).unwrap();
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
            "CANNOT MEASURE: vox id made an identity with vault.tmp a directory"
        );
        assert!(
            o.stderr.contains("identity file (vault.cbor)") && !o.stderr.contains("store"),
            "a vault that cannot be written must be named as the identity file, not the store: {}",
            o.stderr.trim()
        );
        assert!(
            !store && aside == 0,
            "a failed `vox id` must leave nothing behind (store left {store}, kept aside {aside})"
        );
    }
    std::fs::remove_dir(p.dir().join("vault.tmp")).unwrap();
    let o = p.vox(&["id"]);
    let aside = p.kept_aside();
    eprintln!(
        "[proof] obstacle removed: vox id ok={} {}; kept aside {aside}",
        o.ok,
        o.stdout.trim()
    );
    assert!(
        o.ok && aside == 0,
        "the retry must make the identity and keep nothing aside"
    );

    // (b) a leftover store: a failed attempt puts it back where it was, untouched.
    let q = Profile::new(tmp.path(), "leftover-then-fail");
    let first = q.vox(&["id"]);
    assert!(
        first.ok,
        "CANNOT MEASURE: the first vox id: {}",
        first.stderr
    );
    std::fs::remove_file(q.dir().join("vault.cbor")).unwrap();
    let before = std::fs::read(q.dir().join("store.redb")).unwrap();
    std::fs::create_dir_all(q.dir().join("vault.tmp")).unwrap();
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
        "a failed `vox id` must put the leftover store back where it was, byte for byte"
    );
    std::fs::remove_dir(q.dir().join("vault.tmp")).unwrap();
    let o = q.vox(&["id"]);
    let aside = q.kept_aside();
    eprintln!(
        "[proof] obstacle removed: vox id ok={}; kept aside {aside}",
        o.ok
    );
    assert!(
        o.ok && aside == 1,
        "the retry must make the identity and keep the leftover store aside, once"
    );
}
