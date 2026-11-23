//! Launcher for the release's real-asset apparatus; never selects a cargo product binary.
#![allow(dead_code)]

pub fn run(journey: &str) {
    let script = std::env::var_os("VOX_PROOF_JOURNEY_SCRIPT").unwrap_or_else(|| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/release/journey.py")
            .into_os_string()
    });
    let dist = std::env::var_os("VOX_PROOF_DIST")
        .expect("APPARATUS: VOX_PROOF_DIST must name the exact release asset directory");
    let work = std::env::var_os("VOX_PROOF_JOURNEY_WORK")
        .expect("APPARATUS: VOX_PROOF_JOURNEY_WORK must name a new scratch directory");
    let mut command = std::process::Command::new("python3");
    command
        .arg(script)
        .args([journey, "--dist"])
        .arg(dist)
        .arg("--work")
        .arg(work);
    if let Some(version) = std::env::var_os("VOX_PROOF_EXPECTED_VERSION") {
        command.arg("--expected-version").arg(version);
    }
    if let Some(candidate) = std::env::var_os("VOX_PROOF_CANDIDATE_DIST") {
        command.arg("--candidate-dist").arg(candidate);
    }
    let status = command.status().expect("APPARATUS: start release journey");
    assert!(
        status.success(),
        "release {journey} journey failed; its PRODUCT or APPARATUS verdict is above"
    );
}
