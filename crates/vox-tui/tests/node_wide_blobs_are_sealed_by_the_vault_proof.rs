//! V210-40 (#214) — **what a node keeps for its identity is sealed by the identity passphrase, not
//! by anything a quantum adversary can compute from the public key**, through the shipped binary.
//!
//! Three blobs belong to the identity rather than to a room: the trust keyring, the pending
//! consents and the prekey ring. Up to v0.2.9 each was sealed under a key taken from `id_proof`,
//! an Ed25519 signature. Ed25519's private key falls to a quantum adversary holding only the
//! public key, so that adversary, with the disk, could open all three without the passphrase. For
//! the prekey ring that means the ML-KEM prekey secrets, which undo the post-quantum half of
//! every handshake recorded against them. They are now sealed from `self_seed`, inside the
//! Argon2id vault.
//!
//! The **attacker** here is test-side code reading the store the real binary wrote, after the
//! binary has stopped. It is given exactly the quantum adversary's power: it can sign as the
//! identity, so it can compute any `id_proof`, and it has no `self_seed`.
//!
//! 1. **Fresh profile.** The binary writes all three blobs. The attacker opens none of them; the
//!    vault's own key opens each (the control that the reader works); the vault is version 2.
//! 2. **Migration.** The **released v0.2.9 binary**, fetched and checked against its published
//!    SHA-256, writes a profile. The attacker opens its keyring and prekey ring (the control that
//!    the attacker's keys are the ones v0.2.9 used). The new binary then unlocks it: `vox trust
//!    list` still names the trusted member, the room still reads, and the attacker now opens
//!    nothing.
//! 3. **No way back.** On the migrated profile, the attacker plants a keyring sealed its way,
//!    naming "mallory", and relabels the vault as version 1, which is what makes an unlock
//!    migrate. The binary must never show mallory: the version is bound into the vault's AEAD,
//!    so the relabelled vault does not open at all.
//!
//! Mutations: any one blob sealed with its old key again breaks (1); an unlock that does not
//! migrate breaks (2); the vault's version left out of its AEAD breaks (3).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use vox_core::atrest::sek::{Sek, NONCE_LEN};
use vox_core::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use vox_core::atrest::vault::{IdentityVault, VaultRootSigner};
use vox_core::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use vox_core::node::store::Store;
use vox_core::node::{pending_consent, prekeys, trust};

use world::{args, VoxProc, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(90);

/// The release the migration arm starts from, and its binaries' published SHA-256.
const PREVIOUS: &str = "v0.2.9";
const PREVIOUS_SHA256: &[(&str, &str)] = &[
    (
        "aarch64-apple-darwin",
        "1015a3296541e94bc18ec92af43badc0eeabf98db99a92b4b88553fbea79bd31",
    ),
    (
        "x86_64-apple-darwin",
        "5efb392656f7e87bfbb726167408eca75fa96b49ff572deb25a698fb84388b73",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "7b622d32cffa14eb18cc0471b31b6b85d7da487adb4786016ab42577d9924b3d",
    ),
];

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
        .expect("run vox");
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ok(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> String {
    let (good, out, err) = vox_with(exe, data, argv, stdin);
    assert!(good, "vox {argv:?} failed: {out}{err}");
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
            pass_file.to_str().unwrap(),
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
    panic!("{name}'s daemon never answered `vox room list`");
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid}");
}

/// Create a room on `host`'s daemon, have `guest` join it, and return the room's id.
fn shared_room(exe: &Path, host: &Path, guest: &Path, name: &str) -> String {
    ok(
        exe,
        host,
        &["room", "create", "--name", name],
        Some("room pass"),
    );
    let list = ok(exe, host, &["room", "list"], None);
    let room = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let link = ok(exe, host, &["room", "invite", &room], None);
    ok(
        exe,
        guest,
        &["room", "join", link.trim(), "--name", name],
        Some("room pass"),
    );
    room
}

/// The released binary for this platform, fetched once per target directory and checked against
/// its published SHA-256.
fn previous_release() -> PathBuf {
    let triple = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        other => panic!("CANNOT MEASURE: {PREVIOUS} was not released for {other:?}"),
    };
    let want = PREVIOUS_SHA256
        .iter()
        .find(|(t, _)| *t == triple)
        .map(|(_, h)| *h)
        .unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("vox-{PREVIOUS}"));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join(format!("vox-{triple}"));
    let digest = |p: &Path| hex(&Sha256::digest(std::fs::read(p).unwrap_or_default()));
    if !exe.is_file() || digest(&exe) != want {
        let url = format!(
            "https://github.com/robertelee78/vox/releases/download/{PREVIOUS}/vox-{triple}"
        );
        let part = dir.join("download.part");
        let fetched = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(&url)
            .status()
            .is_ok_and(|s| s.success());
        assert!(fetched, "CANNOT MEASURE: could not fetch {url}");
        assert_eq!(
            digest(&part),
            want,
            "{url} does not match its published SHA-256"
        );
        std::fs::rename(&part, &exe).unwrap();
    }
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- the attacker ----------------------------------------------------------------------------

/// The quantum adversary's power: it can sign as the identity, so any `id_proof` is within
/// reach, and it holds no `self_seed` (`at_rest_seed` is the trait's `None`).
struct IdProofOnly<'a>(&'a VaultRootSigner);

impl RootSigner for IdProofOnly<'_> {
    fn public_key(&self) -> CompositePublicKey {
        self.0.public_key()
    }
    fn sign(&self, msg: &[u8]) -> vox_core::Result<CompositeSignature> {
        self.0.sign(msg)
    }
}

/// A profile as it lies on disk, the binary stopped.
struct Disk {
    vault_file: PathBuf,
    store_file: PathBuf,
}

impl Disk {
    fn of(data: &Path) -> Self {
        let profile = data.join("default");
        Self {
            vault_file: profile.join("vault.cbor"),
            store_file: profile.join("store.redb"),
        }
    }

    fn vault(&self) -> IdentityVault {
        IdentityVault::from_canonical_slice(&std::fs::read(&self.vault_file).unwrap()).unwrap()
    }

    /// The identity, unlocked — for the control and for handing the attacker its signing power.
    fn signer(&self) -> VaultRootSigner {
        self.vault().unlock_signer(IDENTITY.as_bytes()).unwrap()
    }

    fn store(&self) -> Store {
        Store::open_read_only(&self.store_file).unwrap()
    }
}

/// One of the three blobs, as sealed bytes, with how to open it.
struct Blob {
    what: &'static str,
    kind: SegmentKind,
    id: u64,
    sealed: SealedSegment,
}

fn meta_blob(store: &Store, name: &str) -> Option<SealedSegment> {
    let blob = store.get_meta(name).unwrap()?;
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    Some(SealedSegment {
        nonce: nonce.try_into().unwrap(),
        ciphertext: ciphertext.to_vec(),
    })
}

fn blobs(disk: &Disk) -> Vec<Blob> {
    let store = disk.store();
    let mut out = Vec::new();
    if let Some(sealed) = meta_blob(&store, trust::TRUST_META_KEY) {
        out.push(Blob {
            what: "trust keyring",
            kind: SegmentKind::Trust,
            id: trust::TRUST_SEGMENT_ID,
            sealed,
        });
    }
    if let Some(sealed) = meta_blob(&store, pending_consent::META_KEY) {
        out.push(Blob {
            what: "pending consents",
            kind: SegmentKind::Trust,
            id: pending_consent::SEGMENT_ID,
            sealed,
        });
    }
    if let Some(sealed) = store
        .get_segment(
            &prekeys::ring_channel(),
            SegmentKind::PrekeyRing,
            prekeys::SEG_PREKEY_RING,
        )
        .unwrap()
    {
        out.push(Blob {
            what: "prekey ring",
            kind: SegmentKind::PrekeyRing,
            id: prekeys::SEG_PREKEY_RING,
            sealed,
        });
    }
    out
}

/// Every key the attacker can compute for `blob`: the ones v0.2.9 sealed with.
fn attacker_keys(blob: &Blob, attacker: &IdProofOnly<'_>) -> Vec<Sek> {
    match blob.what {
        // v0.2.9 had no pending consents; builds between sealed them under the keyring's key.
        "trust keyring" | "pending consents" => vec![trust::legacy_trust_sek(attacker).unwrap()],
        "prekey ring" => vec![prekeys::legacy_ring_sek(attacker).unwrap()],
        _ => unreachable!(),
    }
}

fn vault_key(blob: &Blob, signer: &VaultRootSigner) -> Sek {
    match blob.what {
        "trust keyring" => trust::trust_sek(signer).unwrap(),
        "pending consents" => pending_consent::pending_consent_sek(signer).unwrap(),
        "prekey ring" => prekeys::ring_sek(signer).unwrap(),
        _ => unreachable!(),
    }
}

/// Which blobs the attacker opens, and which the vault's key opens.
fn who_opens(disk: &Disk) -> (Vec<&'static str>, Vec<&'static str>) {
    let signer = disk.signer();
    let attacker = IdProofOnly(&signer);
    assert!(
        trust::trust_sek(&attacker).is_err(),
        "the attacker must not be able to derive a vault key at all"
    );
    let (mut theirs, mut ours) = (Vec::new(), Vec::new());
    for blob in blobs(disk) {
        if attacker_keys(&blob, &attacker)
            .iter()
            .any(|k| open_segment(k, blob.kind, blob.id, &blob.sealed).is_ok())
        {
            theirs.push(blob.what);
        }
        if open_segment(&vault_key(&blob, &signer), blob.kind, blob.id, &blob.sealed).is_ok() {
            ours.push(blob.what);
        }
    }
    (theirs, ours)
}

fn present(disk: &Disk) -> Vec<&'static str> {
    blobs(disk).iter().map(|b| b.what).collect()
}

// ---- the proof ---------------------------------------------------------------------------------

#[test]
#[ignore = "real vox processes with production Argon2id, and the v0.2.9 release; CI runs it in release"]
fn node_wide_blobs_are_sealed_by_the_vault() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();
    let new = PathBuf::from(VOX);

    // ---- 1. a fresh profile ---------------------------------------------------------------
    let (alice, bob) = (dir("alice"), dir("bob"));
    let bob_fp = ok(&new, &bob, &["id"], None).trim().to_owned();
    ok(&new, &alice, &["id"], None);
    {
        let (_node, spec) = anchor(&new, &dir("anchor"));
        let alice_d = daemon(&new, "alice", &alice, &spec, &idpass);
        let bob_d = daemon(&new, "bob", &bob, &spec, &idpass);
        let room = shared_room(&new, &alice, &bob, "sealed");
        // With bob unreachable, alice's key for him is held until it can be delivered: that is
        // the pending consent, written to disk.
        let bob_pid = bob_d.child.id();
        signal(bob_pid, "-STOP");
        ok(
            &new,
            &alice,
            &["trust", "add", &bob_fp, "--name", "bob"],
            None,
        );
        ok(
            &new,
            &alice,
            &["room", "post", &room, "while bob is away"],
            None,
        );
        std::thread::sleep(Duration::from_secs(3));
        drop(alice_d);
        signal(bob_pid, "-CONT");
        drop(bob_d);
    }
    let disk = Disk::of(&alice);
    let blobs_present = present(&disk);
    for want in ["trust keyring", "pending consents", "prekey ring"] {
        assert!(
            blobs_present.contains(&want),
            "CANNOT MEASURE: the binary wrote no {want} (it wrote {blobs_present:?})"
        );
    }
    let (theirs, ours) = who_opens(&disk);
    let version = disk.vault().version;
    println!("[proof] fresh profile: vault v{version}; the attacker opens {theirs:?}; the vault's key opens {ours:?}");
    assert_eq!(
        ours.len(),
        3,
        "CANNOT MEASURE: the reader opens only {ours:?} with the vault's own key"
    );
    assert!(
        theirs.is_empty(),
        "a quantum adversary without the passphrase opens {theirs:?}"
    );
    assert_eq!(version, 2, "a fresh vault is not version 2");

    // ---- 2. a profile written by v0.2.9 ---------------------------------------------------
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
    let room = {
        let (_node, spec) = anchor(&old, &dir("old-anchor"));
        let _carol_d = daemon(&old, "carol (v0.2.9)", &carol, &spec, &idpass);
        let _dave_d = daemon(&old, "dave (v0.2.9)", &dave, &spec, &idpass);
        let room = shared_room(&old, &carol, &dave, "carried");
        ok(
            &old,
            &carol,
            &["room", "post", &room, "written by v0.2.9"],
            None,
        );
        room
    };
    let disk = Disk::of(&carol);
    let before = present(&disk);
    let (theirs_before, _) = who_opens(&disk);
    let version_before = disk.vault().version;
    println!("[proof] v0.2.9 profile: vault v{version_before}; blobs {before:?}; the attacker opens {theirs_before:?}");
    assert_eq!(
        version_before, 1,
        "CANNOT MEASURE: {PREVIOUS} did not write a version-1 vault"
    );
    for want in ["trust keyring", "prekey ring"] {
        assert!(
            theirs_before.contains(&want),
            "CANNOT MEASURE: the attacker's keys do not open {PREVIOUS}'s {want}, so they are not \
             the keys {PREVIOUS} sealed with, and nothing below would mean anything"
        );
    }

    let listed = ok(&new, &carol, &["trust", "list"], None);
    let (theirs_after, ours_after) = who_opens(&disk);
    let version_after = disk.vault().version;
    let reads = {
        let (_node, spec) = anchor(&new, &dir("new-anchor"));
        let _carol_d = daemon(&new, "carol", &carol, &spec, &idpass);
        ok(&new, &carol, &["room", "read", &room], None)
    };
    println!(
        "[proof] after this build's first unlock: vault v{version_after}; the attacker opens \
         {theirs_after:?}; the vault's key opens {ours_after:?}; `trust list` names dave = {}; \
         the room reads the v0.2.9 post = {}",
        listed.contains("dave"),
        reads.contains("written by v0.2.9")
    );
    assert!(
        listed.contains("dave"),
        "the migrated keyring lost dave: {listed}"
    );
    assert!(
        reads.contains("written by v0.2.9"),
        "the migrated profile cannot read its room: {reads}"
    );
    assert_eq!(
        ours_after.len(),
        before.len(),
        "a blob did not move to the vault's key: {ours_after:?} of {before:?}"
    );
    assert!(
        theirs_after.is_empty(),
        "after migration a quantum adversary still opens {theirs_after:?}"
    );
    assert_eq!(
        version_after, 2,
        "the migrated vault is still version {version_after}"
    );

    // ---- 3. no way back to the old keys -------------------------------------------------------
    // (a) A keyring sealed the attacker's way, under the migrated v2 vault: no loader tries an
    // old key, so it does not open.
    plant_mallory(&disk);
    let (opened, out, err) = vox_with(&new, &carol, &["trust", "list"], None);
    println!(
        "[proof] a planted old-key keyring under the v2 vault: `trust list` succeeded = {opened}, \
         names mallory = {}",
        out.contains("mallory")
    );
    assert!(
        !out.contains("mallory"),
        "a keyring planted with a key computable from the public key was accepted: {out}{err}"
    );
    // (b) The same, with the vault relabelled v1, which is what makes an unlock migrate.
    {
        let mut vault = disk.vault();
        vault.version = 1;
        std::fs::write(&disk.vault_file, vault.to_canonical_vec()).unwrap();
    }
    let (opened, out, err) = vox_with(&new, &carol, &["trust", "list"], None);
    println!(
        "[proof] the same under a vault relabelled v1: `trust list` succeeded = {opened}, names \
         mallory = {}",
        out.contains("mallory")
    );
    assert!(
        !out.contains("mallory"),
        "a keyring planted with a key computable from the public key was accepted: {out}{err}"
    );
    assert!(
        !opened,
        "a v2 vault relabelled v1 still unlocked: {out}{err}"
    );
}

/// The attacker's keyring, naming "mallory", sealed with a key it can compute, over the real one.
fn plant_mallory(disk: &Disk) {
    {
        let signer = disk.signer();
        let attacker = IdProofOnly(&signer);
        let mut planted = trust::Keyring::new();
        planted.trust([7u8; 32], "mallory").unwrap();
        let sealed = seal_segment(
            &trust::legacy_trust_sek(&attacker).unwrap(),
            SegmentKind::Trust,
            trust::TRUST_SEGMENT_ID,
            &planted.to_bytes(),
        )
        .unwrap();
        let store = Store::open(&disk.store_file).unwrap();
        let mut blob = sealed.nonce.to_vec();
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(trust::TRUST_META_KEY, &blob).unwrap();
    }
}
