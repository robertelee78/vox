//! **An optional proof is loud when it is not run** (decider, 2026-10-01). Without vox-tui's
//! `optional-proofs` feature the proof itself is not compiled, so nothing would show it exists:
//! a listing would leave it out and a run would read `running 0 tests … ok`. [`not_run!`] puts a
//! stand-in in its place, under the proof's own name in the module `optional_proof_not_run`:
//!
//! - a listing (`-- --ignored --list`) shows `optional_proof_not_run::<proof>`;
//! - a run without `--ignored` shows it `ignored, OPTIONAL PROOF NOT RUN: …`;
//! - a run with `--ignored` (CI, the release gate) prints `OPTIONAL PROOF NOT RUN: …` past the
//!   test harness's capture, and passes: an optional proof blocks nothing.
//!
//! Each optional proof file includes this with `#[path]` and names its optional tests once:
//!
//! ```ignore
//! #[path = "support/optional_proof.rs"]
//! mod optional_proof;
//! optional_proof::not_run!(a_first_direct_connection_completes_in_under_two_seconds);
//! ```
//!
//! docs/release/optional-proofs.md lists every optional proof and how to run it.

/// One stand-in per optional test named, compiled only without the `optional-proofs` feature.
macro_rules! not_run {
    ($($proof:ident),+ $(,)?) => {
        #[cfg(not(feature = "optional-proofs"))]
        mod optional_proof_not_run {
            $(
                #[test]
                #[ignore = "OPTIONAL PROOF NOT RUN: enable with --features optional-proofs (docs/release/optional-proofs.md)"]
                fn $proof() {
                    use std::io::Write as _;
                    // `eprintln!` is captured for a passing test; a write to the stream is not.
                    let _ = writeln!(
                        std::io::stderr(),
                        "OPTIONAL PROOF NOT RUN: {}::{} needs --features optional-proofs \
                         (docs/release/optional-proofs.md); it blocks nothing",
                        env!("CARGO_CRATE_NAME"),
                        stringify!($proof)
                    );
                }
            )+
        }
    };
}
pub(crate) use not_run;
