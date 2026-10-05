//! ADR-017 4.2 — **`vox serve` names who can reach the service, and who in the room cannot**, by
//! name and not by count, and says it again when either changes. Driven through the shipped
//! binary.
//!
//! It printed the rule alone ("the identities you have trusted, once they join"), so a person
//! serving a port could not see who, of the people in the room, could reach it.
//!
//! Staging, nothing faked: a host `vox serve`s a port; a guest it trusts (as "the guest") joins
//! with the address and passphrase, and so does mallory, whom it does not trust. Then the host
//! trusts mallory with `vox trust add`.
//!
//! Asserted, from what `vox serve` printed (two lines each time: who can reach it, and who in
//! the room cannot):
//! - before anyone joins, nobody can reach it;
//! - with both in the room, "the guest" can reach it, and mallory, by her fingerprint (the thing
//!   a person needs to `vox trust add` her), is in the room and cannot;
//! - once mallory is trusted, both can, by their names, and nobody in the room cannot.
//!
//! Mutation: every member counted as able to reach it (the trust check in
//! `tunnel_cli::audience` taken as true) turns it red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::time::Duration;

use world::{args, fingerprint, mkdir, vox_once, VoxProc, World};

const WITHIN: Duration = Duration::from_secs(60);
const CAN: &str = "can reach it now:";
const CANNOT: &str = "in the room and cannot (not trusted):";

/// The first audience `vox serve` said that satisfies `pred`, as its two lines `(can, cannot)`,
/// waited for; `None` if it said none within [`WITHIN`].
fn audience(host: &mut VoxProc, pred: impl Fn(&str, &str) -> bool) -> Option<(String, String)> {
    let deadline = std::time::Instant::now() + WITHIN;
    loop {
        let said = host.transcript();
        let lines: Vec<&str> = said.lines().map(str::trim).collect();
        let found = lines.windows(2).find_map(|w| {
            let can = w[0].strip_prefix(CAN)?.trim();
            let cannot = w[1].strip_prefix(CANNOT)?.trim();
            pred(can, cannot).then(|| (can.to_owned(), cannot.to_owned()))
        });
        if found.is_some() || std::time::Instant::now() >= deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "an anchor and three vox daemons with production Argon2id; CI runs it in release"]
fn vox_serve_names_who_can_reach_it_and_who_cannot() {
    watchdog::arm();
    let mut w = World::new(world::echo_service(), true);
    let mallory = w.tmp.path().join("mallory");
    mkdir(&mallory.join("cfg"));
    let mallory_fp = fingerprint(&mallory, "mallory");
    let (ok, took, out, err) = w.join(&mallory);
    assert!(
        ok,
        "PRODUCT (staging): mallory's `vox connect` failed after {took:?}: {out}{err}"
    );

    let host = w.host.as_mut().expect("APPARATUS: the world's host runs");
    let alone = audience(host, |_, _| true);
    let both = audience(host, |_, cannot| cannot.contains(&mallory_fp));
    eprintln!("[proof] alone: {alone:?}\n[proof] with the guest and mallory: {both:?}");
    assert!(
        alone
            .as_ref()
            .is_some_and(|(can, cannot)| can == "nobody yet" && cannot == "nobody"),
        "PRODUCT: before anyone joins, `vox serve` must say nobody can reach it; it said \
         {alone:?}:\n{}",
        host.transcript()
    );
    assert!(
        both.as_ref()
            .is_some_and(|(can, cannot)| can == "the guest" && *cannot == mallory_fp),
        "PRODUCT: with the trusted guest and untrusted mallory in the room, `vox serve` must name \
         the guest, by name, as able to reach it, and mallory, by fingerprint ({mallory_fp}), as \
         in the room and unable; it said {both:?}:\n{}",
        host.transcript()
    );

    // mallory is trusted: the lists change, and are said again.
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &mallory_fp, "--name", "mallory"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the host's `vox trust add` of mallory: {out}{err}"
    );
    let host = w.host.as_mut().expect("APPARATUS: the world's host runs");
    let trusted = audience(host, |can, _| can.contains("mallory"));
    eprintln!("[proof] once mallory is trusted: {trusted:?}");
    assert!(
        trusted.as_ref().is_some_and(|(can, cannot)| {
            let mut names: Vec<&str> = can.split(", ").collect();
            names.sort_unstable();
            names == ["mallory", "the guest"] && cannot == "nobody"
        }),
        "PRODUCT: once mallory is trusted, `vox serve` must say both can reach it, by name, and \
         that nobody in the room cannot; it said {trusted:?}:\n{}",
        host.transcript()
    );
}
