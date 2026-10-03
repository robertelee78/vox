//! **A dial that reaches a different node than the one it was told to reach says nothing answers
//! as that node, and names no one** (ADR-011 requirement 38a, ADR-012 N-47; it replaces V210-143's
//! wording), driven through the shipped binary.
//!
//! A host whose anchor listened dual-stack on `[::]:0` could be given a port another process held
//! on IPv4 (macOS hands an ephemeral `[::]:0` such a port), so its IPv4 dial to the anchor reached
//! that other, honest node instead. V210-143 had the dial name who answered. Since the identity
//! exchange, the node at an address proves only the identity it is asked for, and refuses anything
//! else with one refusal that names no one: so the dialler says "nothing at `<address>` answers as
//! `<expected>`", and it cannot — and must not — name who is there (ADR-026 G-1).
//!
//! Staged with two real `vox node`s, A and B, each on `127.0.0.1:0`, and a host started with
//! `vox serve --anchor <A's fingerprint>@<B's address>`: its dial to "A" reaches B. What must hold:
//! - the host's report of that dial says nothing at B's address answers as A;
//! - it does not name B.
//!
//! A red is PRODUCT, quoting what the host said. A node that never printed its spec, or a host that
//! never reported the dial, is PRODUCT (staging).
//!
//! **The mutation that must turn it red:** the dial's refusal reported as a bare handshake failure
//! (`DialFailed::into_error` giving the old "refused the peer" text), so the address and the
//! expected node go unsaid.
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
        "PRODUCT (staging): node {name} printed no `fp@address` spec: {spec:?}"
    );
    (p, spec)
}

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_dial_that_reaches_another_node_names_no_one() {
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
            &format!("{service}={service}"),
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
    // The spec gives B's address as a multiaddr; the dial names the socket address.
    let at = match b_addr.split('/').collect::<Vec<_>>()[..] {
        ["", "ip4", ip, "udp", port] => format!("{ip}:{port}"),
        ["", "ip6", ip, "udp", port] => format!("[{ip}]:{port}"),
        _ => b_addr.to_owned(),
    };
    let names = format!("nothing at {at} answers as {}", short(a_fp));
    eprintln!("[proof] told to reach A at B's address, the host said: {said}");
    assert!(
        said.contains(&names),
        "PRODUCT: a dial that reached another node must say {names:?}; the host said: {said}\n\
         its transcript:\n{}",
        host.transcript()
    );
    assert!(
        !said.contains(&short(b_fp)),
        "PRODUCT: the dial named the node that is at the address ({}); a refusal names no one: \
         {said}",
        short(b_fp)
    );
}
