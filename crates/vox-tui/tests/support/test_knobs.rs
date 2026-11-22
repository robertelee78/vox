//! **The test-only knobs a proof stages its moment with are in the `vox` it runs** (V210-105,
//! #300).
//!
//! The `VOX_TEST_*` variables are compiled into `vox` only with the `test-knobs` feature
//! (`cargo test --features vox-tui/test-knobs`); the binary a person installs has none of them.
//! Without it a knob is an unread variable, and a proof that sets one would run unstaged — and
//! could pass without ever reaching the moment it exists for. So a proof that sets a knob calls
//! [`require`] first: it looks for the knob's name in the binary, which is there exactly when the
//! read is compiled in, and refuses as CANNOT MEASURE, naming the missing feature, when it is not.

/// Refuse as CANNOT MEASURE unless the `vox` under test reads every variable in `knobs`; say so
/// on stderr when it does.
pub fn require(knobs: &[&str]) {
    let bin = env!("CARGO_BIN_EXE_vox");
    let bytes = std::fs::read(bin).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (harness error): reading {bin} to find its test-only knobs: {e}")
    });
    let missing: Vec<&str> = knobs
        .iter()
        .copied()
        .filter(|k| !bytes.windows(k.len()).any(|w| w == k.as_bytes()))
        .collect();
    assert!(
        missing.is_empty(),
        "CANNOT MEASURE (precondition unmet): {bin} does not read {missing:?}: it was built without \
         the `test-knobs` feature, so this proof cannot stage what it measures. Run it with \
         `cargo test --features vox-tui/test-knobs`."
    );
    eprintln!("test-knobs: {bin} reads {}", knobs.join(", "));
}

/// Check the selector on an owned daemon, not merely on the command requesting the run.
#[allow(dead_code)] // Only mutant journeys need a live daemon receipt.
pub fn require_mutant_on_daemon(pid: u32, who: &str) {
    let Ok(mutant) = std::env::var("VOX_MUTANT_FX28") else {
        return;
    };
    let expected = format!("VOX_TEST_FX28_MUTANT={mutant}");
    let process = std::process::Command::new("ps")
        .args(["eww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .expect("APPARATUS: inspect the owned daemon's environment");
    let shown = String::from_utf8_lossy(&process.stdout);
    assert!(
        process.status.success() && shown.split_whitespace().any(|word| word == expected),
        "APPARATUS: {who}'s daemon pid {pid} did not receive {expected}: {shown}"
    );
    eprintln!(
        "[apparatus] {who} daemon pid {pid}: received {expected}, verified process environment"
    );
}

#[allow(dead_code)] // Only armed-mutant acts use this receipt.
pub fn arm_room_mutant(path: &std::path::Path, room: &[u8; 32]) {
    if std::env::var_os("VOX_MUTANT_FX28").is_some() {
        let _ = std::fs::remove_file(path.with_extension("engaged"));
        std::fs::write(path, room).expect("APPARATUS: arm selected-room mutant");
    }
}

#[allow(dead_code)] // Only armed-mutant acts use this receipt.
pub fn require_room_mutant_engaged(path: &std::path::Path) {
    let Ok(mutant) = std::env::var("VOX_MUTANT_FX28") else {
        return;
    };
    let engaged = std::fs::read_to_string(path.with_extension("engaged"))
        .expect("APPARATUS: daemon never engaged the armed mutant");
    assert_eq!(engaged, mutant, "APPARATUS: wrong mutant engaged");
    eprintln!("[apparatus] daemon wrote mutant engagement receipt: {engaged}");
}
