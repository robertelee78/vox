//! R36 — **a `vox tui` that cannot write the identity file names that file**, in the words the
//! CLI prints, through the shipped binary.
//!
//! The TUI showed every file fault as "could not save — reopen the channel": no file named, and
//! advice for a room ("channel") when what failed was the identity. It now shows the fault's own
//! words for a fault its closed set has none for.
//!
//! Staging (`tests/pty/tui_identity_file_unwritable.py`): a fresh data root whose default node's
//! directory holds a directory at `vault.tmp`, where the vault's temporary file must be created;
//! one `vox tui` in a pty opens on its first-run prompt and is given a passphrase, typed and
//! confirmed. Its status line is read through `pyte`. Asserted: it says the identity file
//! (`vault.cbor`) could not be written and to check that the data directory is writable, and says
//! neither "reopen the channel" nor the store; afterwards no `vault.cbor` exists.
//!
//! Which side a red is on: whatever `vox tui` did or failed to do is `PRODUCT:` (the driver's
//! `RED: PRODUCT`, `HUNG at`, the wrong words). Only the driver's own machinery and the staging
//! directories are `APPARATUS:`.
//!
//! Mutation that must turn it red: the TUI's create path mapping every failure to its generic
//! `UiError::Storage` again.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use world::{node_dir, DEFAULT_NODE, IDENTITY, VOX};

const NAMED: &str = "identity file (vault.cbor) could not be written";
const ADVICE: &str = "data directory is writable";

#[test]
#[ignore = "`vox tui` in a pty with production Argon2id; needs pyte (VOX_PYTE_PATH); run in release"]
fn a_tui_names_the_identity_file_it_could_not_write() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", data.display()));
    let blocker = node_dir(&data, DEFAULT_NODE).join("vault.tmp");
    std::fs::create_dir_all(blocker.join("keep"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", blocker.display()));

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pty/tui_identity_file_unwritable.py"
    );
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &data.to_string_lossy(),
            &data.join("cfg").to_string_lossy(),
            IDENTITY,
            "cargo",
        ],
    );
    let said = out.stdout.clone();
    println!(
        "[proof] the TUI driver took {:?}; exit {:?}; its last stage: {:?}",
        out.took, out.code, out.stage
    );
    println!("[proof] tui: {}", said.trim());
    assert!(
        !said.contains("cargo RED: PRODUCT"),
        "PRODUCT: the `vox tui` failed (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    assert!(
        !said.contains("cargo HUNG at"),
        "PRODUCT: the `vox tui` stopped answering (stage {:?}): {said}",
        out.stage
    );
    assert!(
        !out.has_verdict("cargo") && out.code == Some(0) && said.contains("cargo SAID:"),
        "APPARATUS: the TUI driver's own machinery failed (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    let answer = said
        .lines()
        .find_map(|l| l.strip_prefix("cargo SAID: "))
        .unwrap_or_default()
        .to_owned();
    let made = node_dir(&data, DEFAULT_NODE).join("vault.cbor").exists();
    println!(
        "[proof] the TUI said {answer:?}; names the identity file = {}; gives the advice = {}; \
         a vault.cbor exists afterwards = {made}",
        answer.contains(NAMED),
        answer.contains(ADVICE)
    );
    assert!(
        answer.contains(NAMED)
            && answer.contains(ADVICE)
            && !answer.contains("channel")
            && !answer.contains("store"),
        "PRODUCT: a TUI that could not write the identity file did not say so: it said {answer:?}"
    );
    assert!(
        !made,
        "PRODUCT: the create was refused, and yet a vault.cbor exists"
    );
}
