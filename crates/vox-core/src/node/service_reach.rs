//! **What a shared service needs, and how to reach it** (ADR-028 S-3): the ready-to-copy commands
//! for its kind, each carrying its canonical address, and what reaching it from here needs, with
//! whether each holds. Said from this one place by `vox service list`, the TUI and the macOS app.

use std::net::SocketAddr;

use crate::node::ipc::SharedService;

/// The ready-to-copy commands for one shared service, by its kind (ADR-028 S-3): each
/// `(what it is, the command)`, every one carrying the **canonical** address (S-1) so it works
/// pasted on any member's machine. `ssh` and a URL go through the `.vox` proxy; a forward does not.
#[must_use]
pub fn commands(s: &SharedService) -> Vec<(&'static str, String)> {
    let c = &s.canonical;
    match s.kind.as_str() {
        "ssh" => vec![
            ("ssh", format!("ssh $USER@{c}")),
            ("forward", format!("vox forward {c} 127.0.0.1:2222")),
            ("then", "ssh -p 2222 $USER@127.0.0.1".to_owned()),
        ],
        scheme @ ("http" | "https") => {
            let port = if scheme == "http" { 8080 } else { 8443 };
            vec![
                ("open", format!("{scheme}://{c}/")),
                ("forward", format!("vox forward {c} 127.0.0.1:{port}")),
                ("then", format!("{scheme}://127.0.0.1:{port}/")),
            ]
        }
        "dns" => vec![("forward", format!("vox forward {c} 127.0.0.1:5353"))],
        // A forward picks a free port and says which.
        _ => vec![("forward", format!("vox forward {c} 127.0.0.1:0"))],
    }
}

/// What one shared service needs to be reached from here, and whether each holds (ADR-028 S-3):
/// `(the condition, holds, what to do when it does not)`. `proxy` is whether the `.vox` proxy
/// runs, or `None` where that is not known here (its need is then not said).
#[must_use]
pub fn needs(
    s: &SharedService,
    proxy: Option<&Result<SocketAddr, String>>,
) -> Vec<(String, bool, String)> {
    // This node's own share needs neither its own trust nor itself online.
    let theirs = s.by != "you";
    let who = s.by.as_str();
    let mut needs = Vec::new();
    if theirs {
        needs.push((
            format!("{who} trusts this node (as the room's log says)"),
            s.trusts_you,
            format!(
                "{who} must trust this node: there, `vox trust add` the fingerprint `vox id` \
                 prints here"
            ),
        ));
    }
    needs.push((
        "this node is attached".to_owned(),
        true,
        "`vox node attach`".to_owned(),
    ));
    // A forward carries without the proxy; ssh by address and a URL go through it.
    if let Some(proxy) = proxy.filter(|_| matches!(s.kind.as_str(), "ssh" | "http" | "https")) {
        needs.push(match proxy {
            Ok(at) => (
                format!("the .vox proxy is running on {at}"),
                true,
                String::new(),
            ),
            Err(why) => (
                "the .vox proxy is running".to_owned(),
                false,
                format!("not running: {why}"),
            ),
        });
    }
    if theirs {
        needs.push((
            format!("{who} is online"),
            s.online,
            format!("{who} is not reachable now; it is reached when it comes back"),
        ));
    }
    needs
}
