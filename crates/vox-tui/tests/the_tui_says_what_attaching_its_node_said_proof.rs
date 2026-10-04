//! #410 / #409 — **when `vox tui` attaches its node itself, what the attach said is on its screen**,
//! through the shipped binary and the real `vox tui` in a pty.
//!
//! The daemon reads a node's anchors file when it attaches the node (ADR-026), and says what it
//! skipped there: each line it cannot use, that the file names no usable anchor, and that it
//! carries on with none (V210-107). The daemon writes that only to its own log; a person runs the
//! TUI, so when the TUI's own `Use` attached the node it shows those notes in its notice line
//! (`DaemonCore::attach`, 520003cd). Nothing read them off a screen.
//!
//! **Staging.** A node made by `vox id`, then given an anchors file of two lines that cannot be
//! used (a host that does not resolve, a malformed fingerprint). No daemon runs: `vox tui` starts
//! one, finds the node not attached, and asks for its passphrase at its "Attach node" prompt, where
//! it is typed (`tests/pty/tui_attach_notes.py`).
//!
//! **Asserted:** once the TUI shows its node attached, its bottom rows name the anchors file, say
//! it names no usable anchor, and say the TUI's node carries on with no anchor. Each red names its
//! side: what the TUI drew is PRODUCT; a TUI that never asked to attach, or never attached, is
//! PRODUCT (staging); the driver's own machinery (pyte missing) is APPARATUS.
//!
//! **The mutation that must turn it red:** `DaemonCore::attach` not putting the attach's notes in
//! the notice line — red as PRODUCT, the screen saying nothing of the file.

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use world::{args, vox_once, IDENTITY, VOX};

#[test]
#[ignore = "real vox tui in a pty, production Argon2id; needs pyte (VOX_PYTE_PATH)"]
fn the_tui_says_what_attaching_its_node_said() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let bob = tmp.path().join("bob");
    std::fs::create_dir_all(bob.join("cfg")).expect("APPARATUS: cannot make a directory");
    let (ok, fp, err) = vox_once(&bob, &args(&["id"]));
    let fp = fp.trim().to_owned();
    assert!(
        ok && fp.len() == 52,
        "PRODUCT (staging): `vox id` made no node to stage with: {fp:?} {err}"
    );
    let file = bob.join("cfg").join("anchors");
    std::fs::write(
        &file,
        format!("{fp}@no-such-anchor.invalid:4433\nnot-a-fingerprint@127.0.0.1:4433\n"),
    )
    .expect("APPARATUS: cannot write the anchors file");
    let file = file.display().to_string();

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_attach_notes.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &bob.to_string_lossy(),
            &bob.join("cfg").to_string_lossy(),
            IDENTITY,
            "bob",
        ],
    );
    let said = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("bob SAID: "))
        .map(str::to_owned);
    println!(
        "[proof] the TUI driver exited {:?} after {:?} at {:?}; the TUI said: {said:?}",
        out.code, out.took, out.stage
    );
    let Some(said) = said else {
        let side = if out.stdout.contains("bob RED: PRODUCT") || out.stdout.contains("bob HUNG at")
        {
            "PRODUCT (staging)"
        } else {
            "APPARATUS"
        };
        panic!(
            "{side}: the TUI driver did not read the screen of an attached TUI (exit {:?}, stage \
             {:?}):\n{}",
            out.code, out.stage, out.stdout
        );
    };
    let names_file = said.contains(&file) || said.contains("anchors");
    let no_usable = said.contains("names no usable anchor");
    let carries_on = said.contains("carrying on with no anchor");
    println!(
        "[proof] the notice line names the anchors file: {names_file}; says it names no usable \
         anchor: {no_usable}; says it carries on: {carries_on}"
    );
    assert!(
        names_file && no_usable && carries_on,
        "PRODUCT: the TUI attached its node, whose anchors file ({file}) names no usable anchor, \
         and its screen does not say so: it said {said:?}\n[the screen]\n{}",
        out.stdout
    );
}
