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
//! 2. **No way back.** On that profile, stopped, the attacker plants a keyring sealed its way,
//!    naming "mallory": no loader tries a key the attacker can compute, so the binary never shows
//!    mallory, and says the data will not open under a correct passphrase, not that the
//!    passphrase is wrong. The vault relabelled with another version does not open at all.
//!
//! The attacker's keys include the ones releases before v0.3.0 sealed with (`HKDF(id_proof)`),
//! derived here, in the test. (The arms that migrated a v0.2.9 profile went with that migration,
//! #423: Vox carries no code for data from earlier releases.)
//!
//! Mutations: any one blob sealed under a key from `id_proof`, or from anything public, breaks
//! (1); a loader that falls back to such a key breaks (2); the refusal reported as a wrong
//! passphrase breaks (2); the vault's version left out of its AEAD breaks (2)'s relabelled vault.

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
/// The vault versions this test's reader knows: this build's (2).
const KNOWN_VAULT_VERSIONS: [u8; 1] = [2];

// ---- driving the `vox` binary --------------------------------------------------------------

fn vox_with(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(exe);
    cmd.args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE");
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if world::typed::is_keyring_change(argv) {
        let (ok, shown) = world::typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not start {}: {e}", exe.display()));
    if let Some(s) = stdin {
        child
            .stdin
            .take()
            .expect("APPARATUS: vox's stdin")
            .write_all(s.as_bytes())
            .unwrap_or_else(|e| panic!("PRODUCT (staging): vox exited without reading its stdin (could not write vox {argv:?}'s stdin): {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for vox {argv:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vox trust list` run as ADR-026 L-2 has a person run it: a one-shot verb acts only on an
/// attached node, so the node is attached first (`vox node attach default`, which starts the data
/// root's daemon and unlocks the identity there), the list is read, and the
/// node is detached again, its daemon gone, before the proof reads the disk. An attach that fails
/// is the result: the unlock is where a refusal now comes from.
fn trust_list(exe: &Path, data: &Path) -> (bool, String, String) {
    let (attached, out, err) = vox_with(exe, data, &["node", "attach", "default"], None);
    if !attached {
        return (false, out, err);
    }
    let listed = vox_with(exe, data, &["trust", "list"], None);
    let _ = vox_with(exe, data, &["node", "detach", "default"], None);
    daemon_gone(data);
    listed
}

/// Wait up to 15 s for the daemon of `data` to exit (an auto-started daemon goes once its last
/// node detaches, ADR-026 L-8), so the store it held is let go.
fn daemon_gone(data: &Path) {
    let Some(pid) = std::fs::read_to_string(data.join(".daemon/lock"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
    else {
        return;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline
        && Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn ok(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> String {
    let (good, out, err) = vox_with(exe, data, argv, stdin);
    assert!(good, "PRODUCT: vox {argv:?} failed: {out}{err}");
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
            pass_file.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]),
        &[],
    );
    let deadline = Instant::now() + TIMEOUT;
    let mut last = (String::new(), String::new());
    while Instant::now() < deadline {
        let (answered, out, err) = vox_with(exe, data, &["room", "list"], None);
        if answered {
            return p;
        }
        last = (out, err);
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut p = p;
    panic!(
        "PRODUCT: {name}'s daemon never answered `vox room list` within {TIMEOUT:?}; the last \
         answer: {}{}\n--- the daemon said:\n{}",
        last.0,
        last.1,
        p.transcript()
    );
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: `kill {sig} {pid}` did not take");
}

/// Create a room on `host`'s daemon, have `guest` join it, and return the room's id.
///
/// The room passphrase goes on stdin (`--passphrase-file -`).
fn shared_room(exe: &Path, host: &Path, guest: &Path, name: &str) -> String {
    let from_stdin: &[&str] = &["--passphrase-file", "-"];
    let create = [&["room", "create"][..], from_stdin, &["--name", name]].concat();
    ok(exe, host, &create, Some("room pass"));
    let list = ok(exe, host, &["room", "list"], None);
    let room = list
        .lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("PRODUCT: `vox room list` does not name the room {name:?} just created: {list}")
        })
        .to_owned();
    // `vox room link` in this build; the previous release names it `invite`.
    let link_verb = if exe == Path::new(VOX) {
        "link"
    } else {
        "invite"
    };
    let link = ok(exe, host, &["room", link_verb, &room], None);
    let join = [
        &["room", "join"][..],
        from_stdin,
        &[link.trim(), "--name", name],
    ]
    .concat();
    ok(exe, guest, &join, Some("room pass"));
    room
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
    /// The default node as this build keeps it, `<data>/nodes/default/` (ADR-026 §7).
    fn of(data: &Path) -> Self {
        Self::in_dir(&world::node_dir(data, world::DEFAULT_NODE))
    }

    fn in_dir(profile: &Path) -> Self {
        Self {
            vault_file: profile.join("vault.cbor"),
            store_file: profile.join("store.redb"),
        }
    }

    /// The vault as the binary wrote it. A file the test's reader cannot parse is told apart:
    /// a vault version this reader does not know is the reader's fault (APPARATUS); any other
    /// failure is a file the binary wrote wrong (PRODUCT).
    fn vault(&self) -> IdentityVault {
        let path = self.vault_file.display();
        let bytes = std::fs::read(&self.vault_file).unwrap_or_else(|e| {
            panic!("PRODUCT: the binary left no readable vault at {path}: {e}")
        });
        IdentityVault::from_canonical_slice(&bytes).unwrap_or_else(|e| {
            // A canonical vault opens with a 5-array (0x85) and its version as a small uint.
            match (bytes.first(), bytes.get(1)) {
                (Some(0x85), Some(&v)) if v < 0x18 && !KNOWN_VAULT_VERSIONS.contains(&v) => panic!(
                    "APPARATUS: the test's reader knows vault versions {KNOWN_VAULT_VERSIONS:?}, \
                     and {path} is version {v}: {e}"
                ),
                _ => panic!(
                    "PRODUCT: the binary wrote a vault at {path} that does not parse as a vault \
                     ({} bytes, starting {:02x?}): {e}",
                    bytes.len(),
                    &bytes[..bytes.len().min(8)]
                ),
            }
        })
    }

    /// The identity, unlocked — for the control and for handing the attacker its signing power.
    fn signer(&self) -> VaultRootSigner {
        self.vault()
            .unlock_signer(IDENTITY.as_bytes())
            .unwrap_or_else(|e| {
                panic!(
                    "PRODUCT: the vault the binary wrote does not unlock under the passphrase it \
                     was given: {e}"
                )
            })
    }

    fn store(&self) -> Store {
        Store::open_read_only(&self.store_file).unwrap_or_else(|e| match e {
            vox_core::Error::ProfileBusy => panic!(
                "PRODUCT: a vox process the test stopped still holds {}",
                self.store_file.display()
            ),
            e => panic!(
                "PRODUCT: the binary left a store at {} that does not open: {e}",
                self.store_file.display()
            ),
        })
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
    let blob = store
        .get_meta(name)
        .unwrap_or_else(|e| panic!("PRODUCT: the binary's store does not read meta {name}: {e}"))?;
    assert!(
        blob.len() > NONCE_LEN,
        "PRODUCT: the binary stored meta {name} as {} bytes, too short to be sealed",
        blob.len()
    );
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    Some(SealedSegment {
        nonce: nonce
            .try_into()
            .expect("APPARATUS: split_at gave a NONCE_LEN nonce"),
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
        .unwrap_or_else(|e| {
            panic!("PRODUCT: the binary's store does not read the prekey ring: {e}")
        })
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

/// The key a blob was sealed under before v0.3.0, `HKDF(HKDF(id_proof(context)), info)`: what a
/// quantum adversary computes from the public key alone. Derived here, in the test; no code for it
/// is left in vox (#423).
fn id_proof_key(attacker: &IdProofOnly<'_>, context: &[u8; 32], info: &[u8]) -> Sek {
    use vox_core::atrest::{IdentityFactor as _, SignatureIdentityFactor};
    let factor = SignatureIdentityFactor::new(attacker)
        .factor_id(context)
        .expect("APPARATUS: the attacker signs as the identity");
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, factor.as_ref())
        .expand(info, key.as_mut())
        .expect("APPARATUS: HKDF of a 32-byte key");
    Sek::from_bytes(key)
}

/// The labels releases before v0.3.0 sealed the keyring and the prekey ring under.
const OLD_TRUST_INFO: &[u8] = b"vox/trust-keyring-sek/v1";
const OLD_RING_INFO: &[u8] = b"vox/prekey-ring-sek/v1";

/// The old keyring key: over the keyring's context.
fn old_trust_key(attacker: &IdProofOnly<'_>) -> Sek {
    id_proof_key(
        attacker,
        &Sha256::digest(trust::TRUST_CONTEXT_LABEL).into(),
        OLD_TRUST_INFO,
    )
}

/// Every key the attacker can compute for `blob`: the ones releases before v0.3.0 sealed with, and the blob's
/// current label expanded over everything public about the identity. The second set catches a
/// seal whose seed is not secret at all (a verifier's mutant: the seed replaced by a hash of
/// the fingerprint), which the first set alone would miss.
fn attacker_keys(blob: &Blob, attacker: &IdProofOnly<'_>) -> Vec<Sek> {
    let (legacy, label) = match blob.what {
        // Pending consents were sealed under the keyring's key before v0.3.0.
        "trust keyring" => (old_trust_key(attacker), trust::TRUST_SEK_INFO),
        "pending consents" => (
            old_trust_key(attacker),
            pending_consent::PENDING_CONSENT_SEK_INFO,
        ),
        "prekey ring" => (
            id_proof_key(attacker, &prekeys::ring_channel(), OLD_RING_INFO),
            prekeys::PREKEY_RING_SEK_INFO,
        ),
        other => unreachable!("APPARATUS: the proof names no blob {other:?}"),
    };
    let public = attacker.public_key();
    let fp = public.fingerprint();
    let seeds: Vec<Vec<u8>> = vec![
        fp.to_vec(),
        Sha256::digest(fp).to_vec(),
        public.ed25519_bytes().to_vec(),
        public.ml_dsa_bytes().to_vec(),
        public.to_bytes().to_vec(),
        Sha256::digest(public.to_bytes()).to_vec(),
        vec![0u8; 32],
    ];
    let mut keys = vec![legacy];
    for seed in seeds {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, &seed)
            .expand(label, key.as_mut())
            .expect("APPARATUS: HKDF of a 32-byte key");
        keys.push(Sek::from_bytes(key));
    }
    keys
}

fn vault_key(blob: &Blob, signer: &VaultRootSigner) -> Sek {
    match blob.what {
        "trust keyring" => {
            trust::trust_sek(signer).expect("PRODUCT: the binary's vault yields no keyring key")
        }
        "pending consents" => pending_consent::pending_consent_sek(signer)
            .expect("PRODUCT: the binary's vault yields no pending-consent key"),
        "prekey ring" => prekeys::ring_sek(signer)
            .expect("PRODUCT: the binary's vault yields no prekey-ring key"),
        other => unreachable!("APPARATUS: the proof names no blob {other:?}"),
    }
}

/// Which blobs the attacker opens, and which the vault's key opens.
fn who_opens(disk: &Disk) -> (Vec<&'static str>, Vec<&'static str>) {
    let signer = disk.signer();
    let attacker = IdProofOnly(&signer);
    assert!(
        trust::trust_sek(&attacker).is_err(),
        "PRODUCT: the attacker derives a vault key without the passphrase"
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
#[ignore = "real vox processes with production Argon2id; CI runs it in release"]
fn node_wide_blobs_are_sealed_by_the_vault() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile dir");
        d
    };
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: the passphrase file");
    let new = PathBuf::from(VOX);

    // ---- 1. a fresh profile ---------------------------------------------------------------
    let (alice, bob) = (dir("alice"), dir("bob"));
    let bob_fp = ok(&new, &bob, &["id"], None).trim().to_owned();
    ok(&new, &alice, &["id"], None);
    {
        let (_node, spec) = anchor(&new, &dir("anchor"));
        let alice_d = daemon(&new, "alice", &alice, &spec, &idpass);
        let bob_d = daemon(&new, "bob", &bob, &spec, &idpass);
        shared_room(&new, &alice, &bob, "sealed");
        // With bob unreachable, alice's key for him is held until it can be delivered: that is
        // the pending consent, written to disk.
        let bob_pid = bob_d.child.id();
        signal(bob_pid, "-STOP");
        // A consent whose key cannot be delivered now is held on disk: the pending consents.
        // Since V210-45 a first trust is dated in the profile's consent order and needs no held
        // key, so the path that holds one is a **re-trust** after a revocation, whose consent is
        // dated by its delivery (ADR-007). Outcomes are not the point here: the blob on disk is
        // checked below.
        for step in [
            vec!["trust", "add", bob_fp.as_str(), "--name", "bob"],
            vec!["trust", "remove", bob_fp.as_str()],
            vec!["trust", "add", bob_fp.as_str(), "--name", "bob"],
        ] {
            let (_, out, err) = vox_with(&new, &alice, &step, None);
            eprintln!(
                "[alice, bob stopped] {step:?}: {}{}",
                out.trim(),
                err.trim()
            );
        }
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
            "PRODUCT (staging): the binary wrote no {want} (it wrote {blobs_present:?})"
        );
    }
    let (theirs, ours) = who_opens(&disk);
    let version = disk.vault().version;
    println!("[proof] fresh profile: vault v{version}; the attacker opens {theirs:?}; the vault's key opens {ours:?}");
    // The adversary opening anything is the product's fault whatever the reader's control says.
    assert!(
        theirs.is_empty(),
        "PRODUCT: a quantum adversary without the passphrase opens {theirs:?}"
    );
    assert_eq!(
        ours.len(),
        3,
        "APPARATUS, CANNOT MEASURE: the reader opens only {ours:?} with the vault's own key"
    );
    assert_eq!(version, 2, "PRODUCT: a fresh vault is not version 2");

    // ---- 2. no way back to the old keys -------------------------------------------------------
    // (a) A keyring sealed the attacker's way, under the v2 vault: no loader tries such a key,
    // so it does not open.
    plant_mallory(&disk);
    let (opened, out, err) = trust_list(&new, &alice);
    println!(
        "[proof] a planted old-key keyring under the v2 vault: `trust list` succeeded = {opened}, \
         names mallory = {}",
        out.contains("mallory")
    );
    assert!(
        !out.contains("mallory"),
        "PRODUCT: a keyring planted with a key computable from the public key was accepted: \
         {out}{err}"
    );
    // And it says why, truthfully: the passphrase was right, so "the passphrase is wrong" would
    // send a person to retype a correct one.
    println!(
        "[proof] the refusal says the sealed data will not open = {}, says the passphrase is wrong = {}",
        err.contains("will not open under it"),
        err.contains("passphrase is wrong")
    );
    assert!(
        err.contains("will not open under it") && !err.contains("passphrase is wrong"),
        "PRODUCT: a keyring that will not open under a correct passphrase was reported as: {err}"
    );
    // (b) The same, with the vault relabelled v1, an earlier release's version: it does not open.
    {
        let mut vault = disk.vault();
        vault.version = 1;
        std::fs::write(&disk.vault_file, vault.to_canonical_vec())
            .expect("APPARATUS: relabelling the vault");
    }
    let (opened, out, err) = trust_list(&new, &alice);
    println!(
        "[proof] the same under a vault relabelled v1: `trust list` succeeded = {opened}, names \
         mallory = {}",
        out.contains("mallory")
    );
    assert!(
        !out.contains("mallory"),
        "PRODUCT: a keyring planted with a key computable from the public key was accepted: \
         {out}{err}"
    );
    assert!(
        !opened,
        "PRODUCT: a v2 vault relabelled v1 still unlocked: {out}{err}"
    );
}

/// The attacker's keyring, naming "mallory", sealed with a key it can compute, over the real one.
fn plant_mallory(disk: &Disk) {
    {
        let signer = disk.signer();
        let attacker = IdProofOnly(&signer);
        let mut planted = trust::Keyring::new();
        planted
            .trust([7u8; 32], "mallory")
            .unwrap_or_else(|e| panic!("APPARATUS: the attacker's keyring: {e}"));
        let sealed = seal_segment(
            &old_trust_key(&attacker),
            SegmentKind::Trust,
            trust::TRUST_SEGMENT_ID,
            &planted.to_bytes(),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: sealing the attacker's keyring: {e}"));
        let store = Store::open(&disk.store_file).unwrap_or_else(|e| {
            panic!("APPARATUS, CANNOT MEASURE: the attacker could not open the stopped store to plant: {e}")
        });
        let mut blob = sealed.nonce.to_vec();
        blob.extend_from_slice(&sealed.ciphertext);
        store
            .put_meta(trust::TRUST_META_KEY, &blob)
            .unwrap_or_else(|e| {
                panic!("APPARATUS, CANNOT MEASURE: planting the attacker's keyring: {e}")
            });
    }
}
