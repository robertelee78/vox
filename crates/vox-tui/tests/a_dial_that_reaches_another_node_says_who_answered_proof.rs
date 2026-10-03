//! **A dial that reaches a different node than the one it was told to reach says who answered**
//! (V210-143), driven through the shipped binary.
//!
//! A host whose anchor listened dual-stack on `[::]:0` could be given a port another process held
//! on IPv4 (macOS hands an ephemeral `[::]:0` such a port), so its IPv4 dial to the anchor reached
//! that other, honest node instead. Its verifier, pinned to the anchor's identity, refused it, and
//! every such refusal was one error, `SignatureInvalid`: the host printed "signature verification
//! failed", which named neither the check that failed, nor the TLS alert, nor who had answered.
//!
//! Staged with two real `vox node`s, A and B, each on `127.0.0.1:0` (not `[::]`, so this proof is
//! not itself exposed to the collision it is about), and a host started with `vox serve --anchor
//! <A's fingerprint>@<B's address>`: its dial to "A" reaches B. What must hold:
//! - the host's report of that dial names the node that answered (B) and the one it expected (A),
//!   and the TLS alert;
//! - A red is PRODUCT, quoting what the host said. A node that never printed its spec, or a host
//!   that never reported the dial, is CANNOT MEASURE.
//!
//! **The mutation that must turn it red:** the verifier no longer records why it refused (V210-143's
//! `VerifiedPeer::reject` removed), so the report carries only quinn's generic reason.
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use world::{args, echo_service, mkdir, tempdir, VoxProc};

/// A `vox node` on `127.0.0.1:0` in `dir`: the process, and its `--anchor` spec `fp@address`.
fn node(dir: &std::path::Path, name: &str) -> (VoxProc, String) {
    mkdir(&dir.join("cfg"));
    let mut p = VoxProc::spawn(name, dir, &args(&["node", "--listen", "127.0.0.1:0"]));
    let spec = p
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    assert!(
        spec.contains('@'),
        "CANNOT MEASURE (precondition unmet): node {name} printed no `fp@address` spec: {spec:?}"
    );
    (p, spec)
}

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_dial_that_reaches_another_node_names_who_answered() {
    watchdog::arm();
    let tmp = tempdir();
    let (_a, a_spec) = node(&tmp.path().join("a"), "node-a");
    let (_b, b_spec) = node(&tmp.path().join("b"), "node-b");
    let (a_fp, _) = a_spec
        .split_once('@')
        .expect("PRODUCT (staging): vox node printed a spec with no '@'");
    let (b_fp, b_addr) = b_spec
        .split_once('@')
        .expect("PRODUCT (staging): vox node printed a spec with no '@'");
    // Told to reach A, at B's address.
    let wrong = format!("{a_fp}@{b_addr}");
    let host_dir = tmp.path().join("host");
    mkdir(&host_dir.join("cfg"));
    let service = echo_service().to_string();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &service,
            "--anchor",
            &wrong,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let said = host.expect_line("the host's report of its dial to the anchor", |l| {
        l.contains("dialling this anchor failed") || l.contains("could not reach")
    });
    let short = |fp: &str| fp.chars().take(26).collect::<String>();
    let names = format!(
        "the peer that answered is {}, not the expected {}",
        short(b_fp),
        short(a_fp)
    );
    eprintln!("[proof] told to reach A at B's address, the host said: {said}");
    assert!(
        said.contains(&names) && said.contains("TLS alert"),
        "PRODUCT: a dial that reached another node must say who answered and who was expected \
         ({names:?}) and the TLS alert; the host said: {said}\nits transcript:\n{}",
        host.transcript()
    );
}
