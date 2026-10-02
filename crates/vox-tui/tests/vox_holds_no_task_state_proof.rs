//! V030-26 (#348) — **Vox holds no task state**: the claim commands are gone, through the shipped
//! `vox` binary.
//!
//! The decider (2026-10-02): "github is the authority, vox is the nagging reminder". Who holds a
//! task is the work item's GitHub issue, maintained through awa; Vox's `claim`, `renew`,
//! `release`, `handoff`, `decline` and `board`, with their fold, leases and version gate, were a
//! second ownership clock, and they are removed.
//!
//! **Asserted**, as a person meets it:
//! - each removed verb is an unknown command: `vox room <verb> --help` fails, and says the
//!   subcommand is not recognised;
//! - `vox room --help` lists none of them;
//! - `vox agent skill`, what an agent reads, names none of them as a command.
//!
//! That a work-bound ask still reaches and wakes its addressee is asserted by
//! `an_agent_wake_is_safe_and_bounded_proof`, case 1, whose urgent ask carries `--work`.
//!
//! **Mutation that must turn it red:** put any one verb back (the `Claim` variant of `RoomCmd`,
//! with its dispatch): its `--help` succeeds, and it is listed.
//!
//! Every red is `PRODUCT:`; there is no staging to fail.

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// The verbs V030-26 removes.
const REMOVED: [&str; 6] = ["claim", "renew", "release", "handoff", "decline", "board"];

fn vox(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(VOX)
        .args(args)
        .env_remove("VOX_ROOM")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn the_claim_commands_are_gone() {
    for verb in REMOVED {
        let (ok, said) = vox(&["room", verb, "--help"]);
        assert!(
            !ok && said.contains("unrecognized subcommand"),
            "PRODUCT: `vox room {verb}` is still a command (exit ok: {ok}):\n{said}"
        );
    }

    let (ok, help) = vox(&["room", "--help"]);
    assert!(ok, "PRODUCT: `vox room --help` failed:\n{help}");
    let listed: Vec<&str> = REMOVED
        .into_iter()
        .filter(|verb| {
            help.lines()
                .any(|l| l.split_whitespace().next() == Some(*verb))
        })
        .collect();
    assert!(
        listed.is_empty(),
        "PRODUCT: `vox room --help` still lists {listed:?}:\n{help}"
    );

    let (ok, skill) = vox(&["agent", "skill"]);
    assert!(ok, "PRODUCT: `vox agent skill` failed:\n{skill}");
    let named: Vec<&str> = REMOVED
        .into_iter()
        .filter(|verb| skill.contains(&format!("vox room {verb}")))
        .collect();
    assert!(
        named.is_empty(),
        "PRODUCT: the agent skill still tells agents to run {named:?}"
    );
}
