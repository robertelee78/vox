//! A deep profile directory must not make the control socket unavailable.
//!
//! Found by running the real thing: `vox daemon` on a profile under a long path
//! died at startup with
//!
//! ```text
//! vox: control socket: profile path bind control socket: …/node.sock: path must be shorter than SUN_LEN
//! ```
//!
//! `sockaddr_un.sun_path` is a fixed 104 bytes on macOS and 108 on Linux. A profile
//! path a person chose for unrelated reasons — a scratch directory, a nested
//! workspace — silently costs them agent comms entirely, with an error that names a
//! C constant and no remedy.
//!
//! So a path that does not fit falls back to `<tmp>/vox-<hex>.sock`, derived from
//! the profile directory. What this proves is the part that makes the fallback
//! usable rather than merely short: it is **deterministic**, so a client computes
//! the same path the daemon bound without being told, and **distinct per profile**,
//! so two nodes on one machine never collide.

use vox_core::node::paths::Paths;

#[test]
fn a_deep_profile_still_gets_a_usable_control_socket() {
    let shallow = std::path::Path::new("/tmp/vx-a");
    let paths = Paths::resolve("default", Some(shallow), Some(shallow)).unwrap();
    let natural = paths.socket_file();
    assert!(
        natural.starts_with(shallow),
        "an ordinary profile keeps its socket beside its vault: {natural:?}"
    );

    // Deep enough to blow sun_path on either platform.
    let deep: std::path::PathBuf = std::path::Path::new("/tmp")
        .join("a".repeat(40))
        .join("b".repeat(40))
        .join("c".repeat(40));
    let paths = Paths::resolve("default", Some(&deep), Some(&deep)).unwrap();
    let fallback = paths.socket_file();

    assert!(
        fallback.as_os_str().len() < 104,
        "the fallback must fit sun_path on macOS, got {} bytes: {fallback:?}",
        fallback.as_os_str().len()
    );
    assert!(
        !fallback.starts_with(&deep),
        "a path that does not fit must not be used: {fallback:?}"
    );

    // Deterministic: the client and the daemon must agree without being told.
    let again = Paths::resolve("default", Some(&deep), Some(&deep))
        .unwrap()
        .socket_file();
    assert_eq!(
        fallback, again,
        "the same profile must always yield the same socket, or a client cannot find its daemon"
    );

    // Distinct: two deep profiles must not collide on one machine.
    let other = std::path::Path::new("/tmp")
        .join("a".repeat(40))
        .join("b".repeat(40))
        .join("d".repeat(40));
    let other = Paths::resolve("default", Some(&other), Some(&other))
        .unwrap()
        .socket_file();
    assert_ne!(
        fallback, other,
        "two profiles sharing one socket would have them fighting over the same node"
    );
}
