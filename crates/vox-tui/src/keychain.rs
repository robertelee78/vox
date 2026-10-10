//! A kept node's identity passphrase in the macOS login keychain (ADR-028 K-10, ADR-014 M-6).
//!
//! Only the daemon touches it: it stores the passphrase when a client (`vox node attach`, `vox
//! node create`, `vox setup`, `vox agent connect`, Vox.app) asks it to keep a node it has just
//! attached with that passphrase (#666), reads it to attach the node again when it starts, and
//! removes it when the node is detached by hand or its passphrase is forgotten. One generic-password item per node, under the
//! service [`SERVICE`] and the node's directory as its account; the item's access is the daemon's
//! own, so reading it back at login asks nothing.

/// The keychain service every kept node's passphrase is stored under.
pub const SERVICE: &str = "us.vox.node";

/// **Test-only** (V210-105, #666): the keychain file a proof's daemon keeps passphrases in, made
/// by the proof with `security create-keychain -p '' <path>`, which changes no preference. Read
/// only in a build with the `test-knobs` feature; no shipped build reads it. With it, every call
/// here goes to that file, unlocked with the empty password, and the Keychain may show nothing:
/// what would ask is refused instead, so no proof can raise a dialog on the machine it runs on.
#[cfg(all(target_os = "macos", feature = "test-knobs"))]
const TEST_KEYCHAIN_ENV: &str = "VOX_TEST_KEYCHAIN";

/// What is said when this Mac has no keychain Vox can use without asking (#666): the node is
/// attached, and not remembered.
pub const NO_KEYCHAIN: &str = "this Mac has no keychain to remember it in; the node will need its \
                               passphrase after a restart";

#[cfg(target_os = "macos")]
mod mac {
    use zeroize::Zeroizing;

    /// **Vox never raises a Keychain window** (#666): no "Keychain Not Found" offering to reset
    /// the person's keychains, no access prompt behind a daemon with no window. Turned off once,
    /// for the life of the process, before the first Keychain call: what would ask fails
    /// instead, and is said in plain words.
    fn quiet() {
        static OFF: std::sync::Once = std::sync::Once::new();
        OFF.call_once(|| {
            std::mem::forget(
                security_framework::os::macos::keychain::SecKeychain::disable_user_interaction(),
            );
        });
    }

    /// `e` in words: the plain line when there is no keychain to use without asking.
    fn said(e: &security_framework::base::Error, what: &str) -> String {
        // errSecNoDefaultKeychain, errSecNoSuchKeychain, errSecInteractionNotAllowed,
        // errSecInteractionRequired.
        if matches!(e.code(), -25307 | -25294 | -25308 | -25315) {
            super::NO_KEYCHAIN.to_owned()
        } else {
            format!("{what}: {e}")
        }
    }

    /// The proof's keychain file, opened and unlocked, with the Keychain's dialogs off for this
    /// process; `None` without the knob.
    #[cfg(feature = "test-knobs")]
    fn test_keychain(
    ) -> Option<Result<security_framework::os::macos::keychain::SecKeychain, String>> {
        use security_framework::os::macos::keychain::SecKeychain;
        let path = std::env::var_os(super::TEST_KEYCHAIN_ENV).filter(|p| !p.is_empty())?;
        // A file that is gone (a proof's directory removed under a daemon still stopping) is
        // refused here: the Keychain, handed a keychain that is not there, offers its own window.
        if !std::path::Path::new(&path).is_file() {
            return Some(Err(format!(
                "the test keychain {} is not there",
                path.to_string_lossy()
            )));
        }
        Some(
            SecKeychain::open(&path)
                .and_then(|mut k| k.unlock(Some("")).map(|()| k))
                .map_err(|e| format!("the test keychain {}: {e}", path.to_string_lossy())),
        )
    }

    /// Store `passphrase` for `account`, replacing what was there.
    pub fn store(account: &str, passphrase: &str) -> Result<(), String> {
        quiet();
        #[cfg(feature = "test-knobs")]
        if let Some(k) = test_keychain() {
            return k?
                .set_generic_password(super::SERVICE, account, passphrase.as_bytes())
                .map_err(|e| format!("the Keychain refused to store it: {e}"));
        }
        security_framework::passwords::set_generic_password(
            super::SERVICE,
            account,
            passphrase.as_bytes(),
        )
        .map_err(|e| said(&e, "the Keychain refused to store it"))
    }

    /// What is stored for `account`, as bytes.
    fn bytes(account: &str) -> Result<Vec<u8>, String> {
        quiet();
        #[cfg(feature = "test-knobs")]
        if let Some(k) = test_keychain() {
            return k?
                .find_generic_password(super::SERVICE, account)
                .map(|(p, _)| p.to_vec())
                .map_err(|e| format!("the Keychain did not give it: {e}"));
        }
        security_framework::passwords::get_generic_password(super::SERVICE, account)
            .map_err(|e| said(&e, "the Keychain did not give it"))
    }

    /// The passphrase stored for `account`.
    pub fn read(account: &str) -> Result<Zeroizing<String>, String> {
        let bytes = Zeroizing::new(bytes(account)?);
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
        quiet();
        #[cfg(feature = "test-knobs")]
        if let Some(k) = test_keychain() {
            if let Ok((_, item)) = k.and_then(|k| {
                k.find_generic_password(super::SERVICE, account)
                    .map_err(|e| e.to_string())
            }) {
                item.delete();
            }
            return;
        }
        let _ = security_framework::passwords::delete_generic_password(super::SERVICE, account);
    }
}

#[cfg(target_os = "macos")]
pub use mac::{forget, read, store};

#[cfg(not(target_os = "macos"))]
const NOT_HERE: &str = "this system has no Keychain Vox can store it in, so after the daemon \
                        restarts the node is to be attached again by hand; or keep it with `vox \
                        node attach <node> --keep --passphrase-file <path>`";

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
