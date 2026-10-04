//! Where a proof's own processes listen (#410): **chosen by the process, then read back**, never
//! picked ahead by the proof and raced for.
//!
//! A port the proof found free by binding and dropping a socket is free only until the next
//! program on the machine takes it, and with proofs running side by side one did: `vox node
//! --listen [::]:<port>` exited 35 ms in with "another program already holds it — Address already
//! in use", and the proof read that as the product failing. So a process listens on port 0 and the
//! proof reads the port it got from what the process says — an anchor's `--anchor` spec, a
//! daemon's `vox status --json` — and a process that could not bind at all is the apparatus's
//! failure, never the product's ([`APPARATUS_BIND`]).
//!
//! A restart that must come back **on the same port** (the case a proof is about) can still find it
//! taken in between; that is said the same way, as APPARATUS.

#![allow(dead_code)]

/// What the product says when the address it was told to listen on is held by another program
/// (`vox_core::error`'s `InUse`, with the OS's own words after it).
pub const IN_USE: &str = "Address already in use";

/// The label for a process of the proof's that could not bind: the run measured nothing about
/// the product.
pub const APPARATUS_BIND: &str = "APPARATUS: a process of the proof's could not listen where the \
                                  proof put it — another program on this machine holds the port";

/// Whether `said` (a process's output) is the product refusing a port another program holds.
#[must_use]
pub fn bind_refused(said: &str) -> bool {
    said.contains(IN_USE)
}

/// The port in an `--anchor` spec (`<fingerprint>@/ip4/<address>/udp/<port>`).
#[must_use]
pub fn spec_port(spec: &str) -> u16 {
    spec.rsplit('/')
        .next()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: no port in the --anchor spec {spec:?}"))
}

/// The loopback address a node listens on, from its own `vox status --json` (`listening`).
#[must_use]
pub fn loopback_listen(status_json: &str) -> Option<std::net::SocketAddr> {
    let v: serde_json::Value = serde_json::from_str(status_json.trim()).ok()?;
    v["listening"]
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|m| vox_core::nat::multiaddr::Multiaddr::parse(m).ok())
        .filter_map(|m| m.socket_addr())
        .find(|a| a.ip().is_loopback())
}
