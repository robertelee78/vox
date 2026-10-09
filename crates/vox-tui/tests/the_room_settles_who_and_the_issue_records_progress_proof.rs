//! V210-131 (#346) — **the agent text says what the room is for and what the issue is for**,
//! through the shipped `vox` binary, as an agent gets it. Run on demand.
//!
//! The decider: GitHub/awa records progress; Vox agent comms records who is making it, and is
//! where agents work through hard problems together. An agent learns that from two places it
//! reads without being asked to look: the skill (`vox agent skill`) and the drain its harness
//! runs every turn (`vox agent hook`). Both must say:
//!
//! 1. who does what is settled in the room: claim work there, ask who is on what there, and
//!    answer a status ask about one's own work there, briefly;
//! 2. the room is where agents work through hard problems together;
//! 3. progress and its proofs are recorded on the GitHub issue through awa, and `--work`
//!    carries awa's work key;
//!
//! and the skill must no longer say the old things: that an attempt starts with a `working`
//! post, that "the tracker — not Vox, not you" owns the item, or that the room is for
//! "planning, assignment and decisions".
//!
//! And V210-166 (#391): `vox agent skill <harness>` names where each of Claude Code, Codex
//! and OpenCode loads it from. The skill is read as an agent gets it: the whole pack, as
//! `vox agent skill --install` (run by the installer and `vox update`) puts it, every file.

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

/// `vox agent skill [harness]`, with no profile of any kind: it reads nothing.
fn skill(harness: Option<&str>) -> (bool, String, String) {
    let mut args = vec!["agent", "skill"];
    args.extend(harness);
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let out = Command::new(VOX)
        .args(&args)
        .env("VOX_DATA_DIR", tmp.path().join("data"))
        .env("VOX_CONFIG_DIR", tmp.path().join("cfg"))
        .output()
        .expect("APPARATUS: run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// What of the split `text` leaves out, by the words that carry each part.
fn missing_split(text: &str, says: &[(&str, &str)]) -> Vec<String> {
    let t = text.to_lowercase();
    says.iter()
        .filter(|(_, w)| !t.contains(&w.to_lowercase()))
        .map(|(part, w)| format!("{part} ({w:?})"))
        .collect()
}

#[test]
#[ignore = "on demand: one networked node with production Argon2id"]
fn the_skill_and_the_drain_say_the_room_settles_who_and_the_issue_records_progress() {
    watchdog::arm();

    // ---- the skill, as the pack an agent reads ----
    let (ok, text, said) = pack();
    assert!(
        ok,
        "PRODUCT: `vox agent skill --install` gave no pack: {said}"
    );
    let missing = missing_split(
        &text,
        &[
            (
                "who does what is settled in the room",
                "The room settles who does what",
            ),
            ("claim work in the room", "Claim work in the room"),
            ("ask who is on what there", "ask there who is on what"),
            ("answer a status ask briefly", "answer there, briefly"),
            (
                "hard problems together",
                "work through hard problems together",
            ),
            (
                "progress goes on the issue",
                "The GitHub issue records progress and its proofs",
            ),
            ("through awa", "through awa"),
            (
                "--work carries awa's key",
                "`--work` carries awa's work key",
            ),
            (
                "progress only on the issue",
                "record progress only on the issue",
            ),
            (
                "who holds only in the room",
                "record who holds a task only in the room",
            ),
        ],
    );
    assert!(
        missing.is_empty(),
        "PRODUCT: the skill an agent reads leaves out: {missing:?}\n{text}"
    );
    let old: Vec<&str> = [
        "your attempt starts when you post `working`",
        "the tracker — not Vox, not you —",
        "planning, assignment and decisions",
        "reporting progress",
    ]
    .into_iter()
    .filter(|o| text.contains(o))
    .collect();
    assert!(
        old.is_empty(),
        "PRODUCT: the skill still tells an agent to keep progress or ownership in the wrong \
         place: {old:?}"
    );
    eprintln!("[proof] the skill carries the split, and none of the old text");

    // ---- where each harness loads it (V210-166) ----
    let (_, entry, _) = skill(None);
    for (h, dir) in [
        ("claude", "~/.claude/skills/vox-agent-comms"),
        ("codex", "${CODEX_HOME:-~/.codex}/skills/vox-agent-comms"),
        (
            "opencode",
            "${XDG_CONFIG_HOME:-~/.config}/opencode/skills/vox-agent-comms",
        ),
    ] {
        let (ok, same, said) = skill(Some(h));
        assert!(
            ok && same == entry && text.starts_with(entry.trim_end()),
            "PRODUCT: `vox agent skill {h}` must print the pack's entry, the same for each"
        );
        assert!(
            said.contains(dir),
            "PRODUCT: `vox agent skill {h}` must say the pack goes in {dir}: {said:?}"
        );
        eprintln!("[proof] {h}: {}", said.trim());
    }

    // ---- the drain, as a harness runs it ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    bob.vox(None, &["room", "post", r, "who is on the codec?"])
        .expect_ok("bob's `vox room post`");
    support::until(
        alice,
        None,
        "bob's question to reach alice",
        &["room", "read", r],
        |o| o.ok && o.stdout.contains("who is on the codec?"),
    );
    let drained = alice.vox(
        Some("agent"),
        &[
            "agent",
            "hook",
            "--node",
            "default",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            "agent",
        ],
    );
    assert!(drained.ok, "PRODUCT: the drain hook failed: {drained:?}");
    let told = &drained.stdout;
    assert!(
        told.contains("who is on the codec?"),
        "APPARATUS: the drain must carry the message, or it proves nothing: {told:?}"
    );
    let missing = missing_split(
        told,
        &[
            (
                "who does what is settled in the room",
                "agents settle who does what",
            ),
            ("claims", "who claims an item"),
            ("who is on what", "who is on what"),
            (
                "a short answer to a status ask",
                "a short answer when asked about one's own work",
            ),
            (
                "hard problems together",
                "work through hard problems together",
            ),
            (
                "progress goes on the issue",
                "recorded on the GitHub issue through awa",
            ),
            (
                "--work carries awa's key",
                "`--work` carries awa's work key",
            ),
        ],
    );
    assert!(
        missing.is_empty(),
        "PRODUCT: the drain an agent reads every turn leaves out: {missing:?}\n{told}"
    );
    eprintln!("[proof] the drain carries the split:\n{told}");
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
