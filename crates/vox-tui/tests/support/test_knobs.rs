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
