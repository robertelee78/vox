//! ADR-017 decision 7 — an anchor may be named by **hostname**, not only by address.
//!
//! The operator's complaint, on configuring the first real always-on anchor:
//! *"we should fix it to where I can specify a hostname not only an ip address
//! that's kind of clunky user experience."* It is worse than clunky — a home
//! connection's address changes when the ISP decides, and every client then holds a
//! spec that silently points nowhere.
//!
//! Resolution happens when the spec is **read**, not on the wire. A `Multiaddr` is
//! the form inside an ADR-016 invite link and has to round-trip byte for byte; a
//! name is a convenience of configuration. So this proves both halves: names work,
//! and nothing about the link form changed.

use vox_core::nat::multiaddr::Multiaddr;
use vox_core::node::link::parse_anchor_spec;

const FP: &str = "cqdzttv3d7ajxr2hrhtap6vif3ji5dbkg6wssyo4tx6qbwo5vnra";

#[test]
fn an_anchor_may_be_named_by_hostname_and_the_wire_form_is_unchanged() {
    // `host:port` — the form a person types.
    let node = parse_anchor_spec(&format!("{FP}@localhost:4433")).expect("host:port");
    let addrs: Vec<Multiaddr> = node.endpoints.addrs().to_vec();
    assert!(!addrs.is_empty(), "a name must yield at least one address");
    assert!(
        addrs
            .iter()
            .all(|a| matches!(a, Multiaddr::Ip4(s) if s.port() == 4433)
                || matches!(a, Multiaddr::Ip6(s) if s.port() == 4433)),
        "every resolved address keeps the port: {addrs:?}"
    );

    // The multiaddr spelling of a name.
    let node = parse_anchor_spec(&format!("{FP}@/dns4/localhost/udp/4433")).expect("/dns4/");
    assert!(
        node.endpoints
            .addrs()
            .iter()
            .all(|a| matches!(a, Multiaddr::Ip4(_))),
        "dns4 must yield only v4: {:?}",
        node.endpoints
    );

    // **The wire form is untouched.** A literal multiaddr still parses exactly as
    // before, which is what keeps ADR-016 invite links round-tripping.
    let node = parse_anchor_spec(&format!("{FP}@/ip4/216.243.48.3/udp/4433")).expect("ip4");
    assert_eq!(
        node.endpoints.addrs().first().map(ToString::to_string),
        Some("/ip4/216.243.48.3/udp/4433".to_owned()),
        "a literal multiaddr must round-trip unchanged"
    );

    // A name that resolves to nothing says so, rather than yielding an anchor that
    // silently cannot be dialled — ADR-017's whole complaint about `--anchor` was
    // that reachability failures are hard to attribute.
    let err = parse_anchor_spec(&format!("{FP}@no-such-host.invalid:4433"));
    assert!(err.is_err(), "an unresolvable name must be refused");

    // Neither a multiaddr nor host:port.
    assert!(parse_anchor_spec(&format!("{FP}@nonsense")).is_err());
}
