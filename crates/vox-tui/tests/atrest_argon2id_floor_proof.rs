//! RP-07 — **the at-rest passphrase factor meets its Argon2id floor** (ADR-010: Argon2id at
//! ≥ 256 MiB and ≥ 3 passes), through the shipped binary.
//!
//! **Staging.** `vox id` — the shipped binary, as a person first runs it — creates an identity
//! and seals it into the profile's vault file (`vault.cbor`) under the identity passphrase.
//!
//! **What is asserted, and why this is the honest measurement.** The test reads the vault the
//! binary wrote and opens it **itself**, with no vox-core code at all: Argon2id over the
//! passphrase and the vault's salt with the floor parameters written here as numbers
//! (262,144 KiB, 3 passes, parallelism 1, 32-byte output), then HKDF-SHA-256 and AES-256-GCM
//! as ADR-010 specifies. AES-GCM authenticates, so the vault opens under that key **only if
//! the binary derived its key with exactly those parameters**. That is a cryptographic fact
//! about the bytes on disk; it does not depend on how busy the machine is.
//!
//! The alternative, asserting that the binary takes at least so long to unlock, is a proxy and
//! is not used. Load only ever makes an unlock slower, so a time floor can pass a weakened KDF
//! on a busy box; and no duration tells 256 MiB × 3 from 128 MiB × 6, or from a sleep. The
//! vault stores only a profile *id*, not the parameters, so reading the id is no proof either:
//! a build that kept id 1 and weakened what id 1 means would read the same.
//!
//! Two controls show the check can fail: the same derivation at half the memory (131,072 KiB)
//! and at one pass fewer (2) must **not** open the vault.
//!
//! This proves the identity vault's passphrase factor. A room's key wrap uses the same
//! production profile (`Argon2Profile::default()`); it lives inside the encrypted store and is
//! not reachable from outside without vox-core, so it is not separately measured here.
//!
//! **Mutation that must turn it red.** Lower `Argon2Profile::PRODUCTION` in
//! `vox-core/src/atrest/sek.rs` (e.g. `m_cost_kib: 128 * 1024`, removing the compile-time
//! floor assertion that would otherwise refuse to build it). The binary then seals the vault
//! under a key the floor parameters do not derive, and the vault does not open.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use world::{args, vox_once, IDENTITY};

/// ADR-010's floor, as numbers — never read from the product.
const FLOOR_M_COST_KIB: u32 = 256 * 1024;
const FLOOR_T_COST: u32 = 3;
const P_COST: u32 = 1;
/// ADR-010's vault key schedule.
const HKDF_INFO: &[u8] = b"vox/identity-vault-wrap/v1";
const AAD: &[u8] = b"vox/identity-vault-aead/v1";

/// The vault as it lies on disk: canonical CBOR
/// `[version, profile_id, salt(16), nonce(12), ciphertext]`. Parsed here, by hand.
struct Vault {
    version: u64,
    profile_id: u64,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn cbor_head(buf: &[u8], at: &mut usize, major: u8) -> u64 {
    let b = buf[*at];
    assert_eq!(
        b >> 5,
        major,
        "CANNOT MEASURE: vault CBOR major type at byte {at}"
    );
    *at += 1;
    let info = b & 0x1f;
    let n = match info {
        0..=23 => return u64::from(info),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => panic!("CANNOT MEASURE: indefinite CBOR in the vault"),
    };
    let mut v = 0u64;
    for _ in 0..n {
        v = (v << 8) | u64::from(buf[*at]);
        *at += 1;
    }
    v
}

fn cbor_bytes(buf: &[u8], at: &mut usize) -> Vec<u8> {
    let len = usize::try_from(cbor_head(buf, at, 2)).unwrap();
    let out = buf[*at..*at + len].to_vec();
    *at += len;
    out
}

fn parse_vault(buf: &[u8]) -> Vault {
    let mut at = 0;
    assert_eq!(cbor_head(buf, &mut at, 4), 5, "CANNOT MEASURE: vault arity");
    let version = cbor_head(buf, &mut at, 0);
    let profile_id = cbor_head(buf, &mut at, 0);
    let salt = cbor_bytes(buf, &mut at);
    let nonce = cbor_bytes(buf, &mut at);
    let ciphertext = cbor_bytes(buf, &mut at);
    assert_eq!(at, buf.len(), "CANNOT MEASURE: trailing bytes in the vault");
    Vault {
        version,
        profile_id,
        salt,
        nonce,
        ciphertext,
    }
}

/// Whether the vault opens under a key derived with these Argon2id parameters.
fn opens_with(v: &Vault, m_cost_kib: u32, t_cost: u32) -> bool {
    let params = argon2::Params::new(m_cost_kib, t_cost, P_COST, Some(32)).unwrap();
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut factor = [0u8; 32];
    argon
        .hash_password_into(IDENTITY.as_bytes(), &v.salt, &mut factor)
        .unwrap();
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &factor)
        .expand(HKDF_INFO, &mut key)
        .unwrap();
    Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&v.nonce),
            Payload {
                msg: &v.ciphertext,
                aad: AAD,
            },
        )
        .is_ok()
}

fn find(dir: &Path, name: &str, found: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            find(&p, name, found);
        } else if p.file_name().is_some_and(|n| n == name) {
            found.push(p);
        }
    }
}

#[test]
#[ignore = "production Argon2id, three derivations in the test; run in release"]
fn the_vault_the_binary_writes_opens_only_under_the_adr_floor() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("person");
    std::fs::create_dir_all(data.join("cfg")).unwrap();

    let (ok, fp, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: `vox id` failed: {err}");
    println!("[proof] `vox id` created identity {}", fp.trim());

    let mut vaults = Vec::new();
    find(&data, "vault.cbor", &mut vaults);
    assert_eq!(
        vaults.len(),
        1,
        "CANNOT MEASURE: expected one vault file under the profile, found {vaults:?}"
    );
    let bytes = std::fs::read(&vaults[0]).unwrap();
    let v = parse_vault(&bytes);
    println!(
        "[proof] vault {}: {} bytes, version {}, profile id {}, salt {} B, nonce {} B, \
         ciphertext {} B",
        vaults[0].display(),
        bytes.len(),
        v.version,
        v.profile_id,
        v.salt.len(),
        v.nonce.len(),
        v.ciphertext.len()
    );
    assert_eq!(
        (v.salt.len(), v.nonce.len()),
        (16, 12),
        "CANNOT MEASURE: the vault's salt and nonce are not the ADR-010 sizes"
    );

    let at_floor = opens_with(&v, FLOOR_M_COST_KIB, FLOOR_T_COST);
    let half_memory = opens_with(&v, FLOOR_M_COST_KIB / 2, FLOOR_T_COST);
    let one_pass_fewer = opens_with(&v, FLOOR_M_COST_KIB, FLOOR_T_COST - 1);
    println!(
        "[proof] opens with Argon2id({FLOOR_M_COST_KIB} KiB, {FLOOR_T_COST} passes): {at_floor}; \
         with half the memory: {half_memory}; with one pass fewer: {one_pass_fewer}"
    );
    assert!(
        at_floor,
        "the vault `vox id` wrote does not open under Argon2id at the ADR-010 floor \
         ({FLOOR_M_COST_KIB} KiB, {FLOOR_T_COST} passes, parallelism {P_COST}): the binary \
         derived its identity key with other parameters (opens with half the memory: \
         {half_memory}; with one pass fewer: {one_pass_fewer}). If they were raised deliberately, \
         change the numbers here; if they were lowered, the at-rest factor is below its floor"
    );
    assert!(
        !half_memory && !one_pass_fewer,
        "CANNOT MEASURE: the vault opened under parameters other than the floor's, so opening \
         proves nothing about which were used"
    );
}
