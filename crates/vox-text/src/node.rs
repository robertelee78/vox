//! What a client says where a node is made, word for word in the CLI, the TUI and the app
//! (ADR-028 K-8), so they never drift apart.

/// A node made with no identity passphrase (ADR-005 J-2, V030-36: optional): what that means,
/// said once where the empty one is given.
pub const NO_PASSPHRASE: &str = "no identity passphrase: this node's identity key is kept on this \
     machine unencrypted, so anyone who can read its data folder can act as this node; a \
     passphrase is encouraged";

/// A node has no backup, so a lost machine means a new node, which the people who trusted the old
/// one remove from their keyrings.
pub const NO_BACKUP: &str = "there is no backup of a node: if this machine is lost, so is this \
     node; make a new one, and ask everyone who trusts this one to remove it from their keyring \
     and trust the new one";
