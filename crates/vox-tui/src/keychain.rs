//! A kept node's identity passphrase in the macOS login keychain (ADR-028 K-10, ADR-014 M-6).
//!
//! Only the daemon touches it: it stores the passphrase when Vox.app asks it to keep a node it has
//! just attached with that passphrase, reads it to attach the node again when it starts, and
//! removes it when the node is detached by hand. One generic-password item per node, under the
//! service [`SERVICE`] and the node's directory as its account; the item's access is the daemon's
//! own, so reading it back at login asks nothing.

/// The keychain service every kept node's passphrase is stored under.
pub const SERVICE: &str = "us.vox.node";

#[cfg(target_os = "macos")]
mod mac {
    use zeroize::Zeroizing;

    /// Store `passphrase` for `account`, replacing what was there.
    pub fn store(account: &str, passphrase: &str) -> Result<(), String> {
        security_framework::passwords::set_generic_password(
            super::SERVICE,
            account,
            passphrase.as_bytes(),
        )
        .map_err(|e| format!("the Keychain refused to store it: {e}"))
    }

    /// The passphrase stored for `account`.
    pub fn read(account: &str) -> Result<Zeroizing<String>, String> {
        let bytes = Zeroizing::new(
            security_framework::passwords::get_generic_password(super::SERVICE, account)
                .map_err(|e| format!("the Keychain did not give it: {e}"))?,
        );
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|e| {
                // The refused copy is the passphrase's bytes too.
                drop(Zeroizing::new(e.into_bytes()));
                "what the Keychain holds for it is not text".to_owned()
            })
    }

    /// Remove what is stored for `account`; nothing stored is not an error.
    pub fn forget(account: &str) {
        let _ = security_framework::passwords::delete_generic_password(super::SERVICE, account);
    }
}

#[cfg(target_os = "macos")]
pub use mac::{forget, read, store};

#[cfg(not(target_os = "macos"))]
const NOT_HERE: &str = "the Keychain is macOS's; keep a node with --keep --passphrase-file here";

/// Store `passphrase` for `account`. Not on this platform.
///
/// # Errors
/// Always.
#[cfg(not(target_os = "macos"))]
pub fn store(_account: &str, _passphrase: &str) -> Result<(), String> {
    Err(NOT_HERE.to_owned())
}

/// The passphrase stored for `account`. Not on this platform.
///
/// # Errors
/// Always.
#[cfg(not(target_os = "macos"))]
pub fn read(_account: &str) -> Result<zeroize::Zeroizing<String>, String> {
    Err(NOT_HERE.to_owned())
}

/// Nothing is stored on this platform.
#[cfg(not(target_os = "macos"))]
pub fn forget(_account: &str) {}
