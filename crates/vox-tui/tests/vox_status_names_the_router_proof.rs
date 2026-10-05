//! V030-41 (#415, ADR-012 N-53, N-58) — **`vox status` names the router the operating system
//! routes by, for IPv4 and IPv6**, through the shipped binary.
//!
//! On macOS the gateway was never found: `default_gateway_v4` and `default_gateway_v6` were
//! Linux-only (`/proc/net/route`), so a Mac asked no router for a port mapping. The default
//! route's next hop is now read from the routing socket (`RTM_GET` on `PF_ROUTE`) and shown in
//! `vox status`.
//!
//! **The claim.** For each family, `vox status --json`'s `gateway.<family>.next_hop` equals what
//! `/sbin/route -n get [-inet6] default` says: the same gateway address and the same interface
//! — or no next hop when the system has no default route of that family ("not in table"). The
//! person's form (`vox status`) says the same in words.
//!
//! The staging is a real profile: `vox id`, then `vox status` with the node attached (ADR-026
//! L-2), as a person runs it. The router is this machine's own; nothing is faked.
//!
//! **Which side a red is on.** `vox` naming a different router, interface, or none where the
//! system has one, is `PRODUCT:`. `route` failing to run, or printing something this proof
//! cannot read, is `APPARATUS:`.
//!
//! Mutation: the macOS reader gone (`default_hop` answering `None` for both families, as the
//! Linux-only build did) → red on IPv4 on any Mac with a network, as PRODUCT.
//!
//! **Not staged here:** a link-local IPv6 next hop (`fe80::…%en0`). This proof checks it when the
//! machine it runs on has one (the interface must then match too); a machine without an IPv6
//! default route checks only that none is named.

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::net::IpAddr;
use std::process::Command;

use serde_json::Value;
use world::{args, tempdir, vox_once, Reaper};

/// What `route -n get [-inet6] default` says: `None` for "not in table", else (gateway, interface).
fn system_default(v6: bool) -> Option<(IpAddr, String)> {
    let mut cmd = Command::new("/sbin/route");
    cmd.arg("-n").arg("get");
    if v6 {
        cmd.arg("-inet6");
    }
    let out = cmd
        .arg("default")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run /sbin/route: {e}"));
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    if text.contains("not in table") {
        return None;
    }
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{name}:")).map(str::trim))
            .unwrap_or_else(|| panic!("APPARATUS: route printed no {name}:\n{text}"))
            .to_owned()
    };
    // A scoped address prints as `fe80::1%en0`: the scope is the interface, said apart.
    let gateway = field("gateway");
    let addr = gateway.split('%').next().unwrap_or_default();
    let addr: IpAddr = addr.parse().unwrap_or_else(|e| {
        panic!("APPARATUS: route's gateway {gateway:?} is not an address: {e}\n{text}")
    });
    Some((addr, field("interface")))
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn vox_status_names_the_router_the_system_routes_by() {
    watchdog::arm();
    let tmp = tempdir();
    let data = tmp.path().join("profile");
    world::mkdir(&data.join("cfg"));
    let _reaper = Reaper(vec![data.clone()]);
    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");

    let (ok, out, err) = vox_once(&data, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: `vox status --json` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    let report: Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}):\n{out}"));
    let (ok, words, err) = vox_once(&data, &args(&["status"]));
    assert!(
        ok,
        "PRODUCT: `vox status` did not answer.\nstdout:\n{words}\nstderr:\n{err}"
    );
    println!("[proof] vox status --json gateway: {}", report["gateway"]);

    for (family, v6) in [("ipv4", false), ("ipv6", true)] {
        let system = system_default(v6);
        let hop = &report["gateway"][family]["next_hop"];
        println!("[proof] {family}: route says {system:?}; vox says {hop}");
        let line = words
            .lines()
            .skip_while(|l| *l != "gateway")
            .find(|l| l.trim_start().starts_with(family))
            .unwrap_or_else(|| {
                panic!("PRODUCT: `vox status` has no {family} gateway line:\n{words}")
            });
        match system {
            None => {
                assert!(
                    hop.is_null(),
                    "PRODUCT: the system has no {family} default route, but vox names {hop}"
                );
                assert!(
                    line.contains("no default route"),
                    "PRODUCT: `vox status` must say there is no {family} default route: {line:?}"
                );
            }
            Some((addr, interface)) => {
                let said: Option<IpAddr> = hop["address"].as_str().and_then(|a| a.parse().ok());
                assert_eq!(
                    said,
                    Some(addr),
                    "PRODUCT: the system routes {family} by {addr} on {interface}; vox names {hop}"
                );
                assert_eq!(
                    hop["interface"].as_str(),
                    Some(interface.as_str()),
                    "PRODUCT: the {family} next hop {addr} leaves by {interface}; vox names {hop}"
                );
                assert!(
                    line.contains(&format!("next hop {addr} via {interface}")),
                    "PRODUCT: `vox status` must say the {family} next hop {addr} via {interface}: {line:?}"
                );
            }
        }
    }
}
