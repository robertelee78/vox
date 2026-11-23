//! **The skill an agent reads** (`vox agent skill`), through the shipped `vox` binary, as an
//! agent gets it. Run on demand.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::Command;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// The skill pack as an agent reads it: `vox agent skill --install` into a scratch `HOME` where
/// Claude Code is present, every file of the pack it put there, joined. (Ok, the pack, what it said.)
fn pack() -> (bool, String, String) {
    let home = tempfile::tempdir().expect("APPARATUS: a tempdir");
    std::fs::create_dir_all(home.path().join(".claude")).expect("APPARATUS: a harness folder");
    let out = Command::new(VOX)
        .args(["agent", "skill", "--install"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("VOX_DATA_DIR", home.path().join("data"))
        .env("VOX_CONFIG_DIR", home.path().join("cfg"))
        .output()
        .expect("APPARATUS: run vox");
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let dir = home.path().join(".claude/skills/vox-agent-comms");
    let mut files: Vec<std::path::PathBuf> = std::iter::once(dir.join("SKILL.md"))
        .chain(
            std::fs::read_dir(dir.join("references"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path()),
        )
        .collect();
    files[1..].sort();
    let text = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n");
    (out.status.success() && !text.is_empty(), text, said)
}

/// What of the split `text` leaves out, by the words that carry each part.
fn missing_split(text: &str, says: &[(&str, &str)]) -> Vec<String> {
    let t = text.to_lowercase();
    says.iter()
        .filter(|(_, w)| !t.contains(&w.to_lowercase()))
        .map(|(part, w)| format!("{part} ({w:?})"))
        .collect()
}

/// R17 (#19), as the decider restated it: there is no hard lock, and a takeover is a written rule
/// an agent reads in the skill, not code. `vox agent skill` must say that another agent may take
/// over a claimed item only after **three** unanswered status asks to the holder, the **last
/// urgent**, spread over **at least 30 minutes**, and that a holder who answers keeps it.
#[test]
#[ignore = "on demand: drives the shipped binary"]
fn the_skill_says_when_a_silent_holder_may_be_taken_over() {
    watchdog::arm();
    let (ok, text, said) = pack();
    assert!(
        ok,
        "PRODUCT: `vox agent skill --install` gave no pack: {said}"
    );
    let missing = missing_split(
        &text,
        &[
            ("no lock", "Nobody locks an item"),
            (
                "a holder who answers keeps it",
                "nobody may take one from\na holder who answers",
            ),
            ("three asks", "three times"),
            ("none answered", "of the three was answered"),
            ("the last urgent", "the **last** of the three was urgent"),
            ("at least 30 minutes", "at least 30 minutes"),
            (
                "the holder answering ends it",
                "If the holder answers at any point",
            ),
        ],
    );
    assert!(
        missing.is_empty(),
        "PRODUCT: the skill's takeover rule (R17) leaves out: {missing:?}\n{text}"
    );
    eprintln!("[proof] R17: the skill states the takeover rule: three unanswered asks, the last urgent, over 30 minutes");
}
