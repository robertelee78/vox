//! What a client says where a node is made, word for word in the CLI, the TUI and the app
//! (ADR-028 K-8), so they never drift apart.

/// A node has no backup, so a lost machine means a new node, which the people who trusted the old
/// one remove from their keyrings.
pub const NO_BACKUP: &str = "there is no backup of a node: if this machine is lost, so is this \
     node; make a new one, and ask everyone who trusts this one to remove it from their keyring \
     and trust the new one";
