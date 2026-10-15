//! **What a shared service needs, and how to reach it** (ADR-028 S-3): the ready-to-copy commands
//! for its kind, each carrying its canonical address, and what reaching it from here needs, with
//! whether each holds. Said from this one place by `vox service list`, the TUI and the macOS app.

use std::net::SocketAddr;

use crate::node::ipc::SharedService;

/// The ready-to-copy commands for one shared service, by its kind (ADR-028 S-3): each
/// `(what it is, the command)`, every one carrying the **canonical** address (S-1) so it works
/// pasted on any member's machine. `ssh` and a URL go through the `.vox` proxy; a forward does not.
#[must_use]
pub fn commands(s: &SharedService, node: &str) -> Vec<(&'static str, String)> {
    use vox_text::shell::{command, node_command};
    let c = &s.canonical;
    let forward =
        |port: u16| node_command(&["vox", "forward", c, &format!("127.0.0.1:{port}")], node);
    match s.kind.as_str() {
        "ssh" => vec![
            ("ssh", command(&["ssh", c])),
            ("forward", forward(2222)),
            ("then", command(&["ssh", "-p", "2222", "127.0.0.1"])),
        ],
        scheme @ ("http" | "https") => {
            let port = if scheme == "http" { 8080 } else { 8443 };
            let opener = if cfg!(target_os = "macos") {
                "open"
            } else {
                "xdg-open"
            };
            vec![
                ("open", command(&[opener, &format!("{scheme}://{c}/")])),
                ("forward", forward(port)),
                (
                    "then",
                    command(&[opener, &format!("{scheme}://127.0.0.1:{port}/")]),
                ),
            ]
        }
        "dns" => vec![("forward", forward(5353))],
        _ => vec![("forward", forward(0))],
    }
}

/// Browser setup is guidance, not a checked readiness fact: Vox knows its proxy's listener,
/// but cannot inspect the default browser's proxy or DNS settings.
#[must_use]
pub fn browser_hint(
    s: &SharedService,
    proxy: Option<&Result<SocketAddr, String>>,
) -> Option<String> {
    if !matches!(s.kind.as_str(), "http" | "https") {
        return None;
    }
    let at = match proxy {
        Some(Ok(at)) => format!(" at {at}"),
        _ => String::new(),
    };
    let unknown = if proxy.is_none() {
        " vox up shows the local proxy address."
    } else {
        ""
    };
    Some(format!(
        "The open command needs your default browser to use the .vox SOCKS5 proxy{at}, \
         with DNS through the proxy. Vox cannot inspect browser settings. \
         The forward and then commands use a local port without browser proxy setup.{unknown}"
    ))
}

/// **What one shared service needs to be reached from here, and whether each holds** (ADR-028
/// S-3, the App Study's readiness ticks): `(the fact, holds, what to do when it does not)`, in the
/// order a person checks them: `.vox proxy running at <address>`, `node Ready`, `<host> trusts
/// you`, `<host> online`. `proxy` is whether the `.vox` proxy runs, or
/// `None` where that is not known here (its fact is then not said).
///
/// Each fact is this node's own knowledge; nothing is asked of anyone for it. `<host> trusts you`
/// is the host's own consent to this node, as the host wrote it into the room's log, never a
/// reading of anybody's keyring. `<host> online` is whether this node holds a live connection to
/// the host now.
#[must_use]
pub fn needs(
    s: &SharedService,
    proxy: Option<&Result<SocketAddr, String>>,
) -> Vec<(String, bool, String)> {
    // This node's own share needs neither its own trust nor itself online.
    let theirs = s.by != "you";
    let who = s.by.as_str();
    let mut needs = Vec::new();
    // A forward carries without the proxy; ssh by address and a URL go through it.
    if let Some(proxy) = proxy.filter(|_| matches!(s.kind.as_str(), "ssh" | "http" | "https")) {
        needs.push(match proxy {
            Ok(at) => (format!(".vox proxy running at {at}"), true, String::new()),
            Err(why) => (
                ".vox proxy running".to_owned(),
                false,
                format!("the .vox proxy is not running: {why}; use the forward command shown for this service without it"),
            ),
        });
    }
    needs.push((
        "node Ready".to_owned(),
        true,
        "unlock this node in Vox or with the node unlock command and its local name".to_owned(),
    ));
    if theirs {
        needs.push((
            format!("{who} trusts you"),
            s.trusts_you,
            format!(
                "{who} must trust this node: on its owning computer, select this node's fingerprint \
                 in the room's trust offers and accept it"
            ),
        ));
        needs.push((
            format!("{who} online"),
            s.online,
            format!("{who} is not reachable now; it is reached when it comes back"),
        ));
    }
    needs
}

/// One fact of [`needs`] as a line, as `vox service list` and the TUI show it: `✓ <fact>` when it
/// holds, `missing: <fact> — <what to do>` when it does not.
#[must_use]
pub fn tick(need: &str, holds: bool, otherwise: &str) -> String {
    if holds {
        format!("✓ {need}")
    } else {
        format!("missing: {need} — {otherwise}")
    }
}
