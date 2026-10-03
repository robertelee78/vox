//! V210-100 (#296) — **a `vox tui` that loses the race to create a profile's identity says that
//! another vox created it**, the same refusal `vox id` gives (V210-91, #285), through the shipped
//! binary.
//!
//! A TUI started on a profile with no identity opens on its first-run "Create identity" prompt.
//! If another vox makes the identity meanwhile, the create the person then confirms finds a vault
//! and is refused. The TUI said "an identity already exists in this profile": true, but it reads
//! as a profile that already had one when the TUI started, and nothing says that this one was not
//! made here, or what to do.
//!
//! Staging (`tests/pty/tui_create_race.py`): two `vox tui`s in ptys on one fresh profile, both on
//! their first-run prompt; the first is given a passphrase and makes the identity, then the second
//! is, and its status line is read through `pyte`. (A one-shot `vox id` started while a TUI runs
//! asks that TUI's node rather than creating anything, so the other creator is a TUI too.)
//! Asserted: the second TUI's answer names the concurrent creation ("another vox created this
//! profile's identity at the same time") and that nothing was created here; afterwards, with both
//! stopped, `vox id` opens the identity the first made.
//!
//! Which side a red is on: whatever a `vox tui` did or failed to do is `PRODUCT:` — no first-run
//! prompt, no identity made, no answer to the second create (the driver's `RED: PRODUCT`), a TUI
//! that stopped reading what is typed (`HUNG at`), the wrong answer, or a profile with no identity
//! after the first TUI made one. Only the driver's own machinery (pyte missing, a crash, a `vox tui`
//! it could not reap) and a temp dir this proof could not make are `APPARATUS:`.
//!
//! Mutation that must turn it red: the TUI's create path mapping the race to the generic
//! `IdentityExists` again — it says "an identity already exists in this profile".

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use world::{vox_once, IDENTITY, VOX};

const NAMED: &str = "another vox created this profile's identity at the same time";
const NOTHING_HERE: &str = "nothing was created here";

#[test]
#[ignore = "`vox tui` in a pty with production Argon2id; needs pyte (VOX_PYTE_PATH); CI runs it in release"]
fn a_tui_that_loses_the_create_race_names_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", data.display()));

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_create_race.py");
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
    // What a `vox tui` failed to do (the driver's `RED: PRODUCT`), or a TUI that stopped reading
    // what is typed (`HUNG at`), is the product's; only the driver's own machinery is the
    // apparatus.
    assert!(
        !said.contains("cargo RED: PRODUCT"),
        "PRODUCT: a `vox tui` in the create race failed (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    assert!(
        !said.contains("cargo HUNG at"),
        "PRODUCT: a `vox tui` in the create race stopped answering (stage {:?}): {said}",
        out.stage
    );
    assert!(
        !out.has_verdict("cargo"),
        "APPARATUS: the TUI driver's own machinery failed (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    assert!(
        out.code == Some(0) && said.contains("cargo SAID:"),
        "APPARATUS: the TUI driver gave no answer to the create (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    let answer = said
        .lines()
        .find_map(|l| l.strip_prefix("cargo SAID: "))
        .unwrap_or_default()
        .to_owned();
    let (ok, now, err) = vox_once(&data, &world::args(&["id"]));
    println!(
        "[proof] the second TUI said {answer:?}; names the concurrent creation = {}; says nothing \
         was created here = {}; `vox id` afterwards: ok = {ok}, {:?}",
        answer.contains(NAMED),
        answer.contains(NOTHING_HERE),
        now.trim()
    );
    assert!(
        ok && !now.trim().is_empty(),
        "PRODUCT: after the first TUI made the identity, `vox id` opens none: {now}{err}"
    );
    assert!(
        answer.contains(NAMED) && answer.contains(NOTHING_HERE),
        "PRODUCT: the TUI that lost the create race did not name it: it said {answer:?}"
    );
}
