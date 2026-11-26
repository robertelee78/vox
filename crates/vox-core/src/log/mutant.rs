//! Deliberately misbehaving sender used only by proof builds.
use crate::log::entry::Entry;

/// What the mutant build says on stderr, and what release packaging refuses to find in a binary.
pub const MARKER: &str = "VOX-MUTANT-SENDER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Correct,
    StripPayload,
    AuthorUnclassifiable,
    AuthorMisbound,
    WithdrawUnentitled,
    AdminUnentitled,
    SplitChain,
}

fn mode() -> Mode {
    static MODE: std::sync::OnceLock<Mode> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        let named = std::env::var("VOX_MUTANT_SENDER_MODE").unwrap_or_default();
        let mode = match named.as_str() {
            "strip-payload" => Mode::StripPayload,
            "author-unclassifiable" => Mode::AuthorUnclassifiable,
            "author-misbound" => Mode::AuthorMisbound,
            "withdraw-unentitled" => Mode::WithdrawUnentitled,
            "admin-unentitled" => Mode::AdminUnentitled,
            "split-chain" => Mode::SplitChain,
            _ => Mode::Correct,
        };
        eprintln!("{MARKER}: this build misbehaves as a sync sender; mode {mode:?} ({named:?})");
        mode
    })
}

/// Whether this build takes a room off boards even where its node may not end it (V030-14): the
/// faulty peer a board must not obey — an admin whose admin was taken back.
#[must_use]
pub fn withdraws_unentitled() -> bool {
    mode() == Mode::WithdrawUnentitled
}

/// Whether this build names admins though its identity is not the room's creator (#319): the
/// admin with a modified client whose certificate no node may honour.
#[must_use]
pub fn admins_unentitled() -> bool {
    mode() == Mode::AdminUnentitled
}

/// `split-chain`: whether this build appends its own entries without checking that each names
/// the one before it (`prev_hash`, `lipmaa_backlink`).
#[must_use]
pub fn splits_chain() -> bool {
    mode() == Mode::SplitChain
}

/// `split-chain`: the own room entry to append in place of `entry`, just signed: the other
/// copy's entry at its position when `VOX_MUTANT_ENTRY_DIR/adopt-<seq>` holds one of this
/// author and room; else `entry`, written to `VOX_MUTANT_ENTRY_DIR/<seq>` for the other copy.
#[must_use]
pub fn own_entry(entry: Entry) -> Entry {
    if mode() != Mode::SplitChain || entry.skeleton.v2.is_none() {
        return entry;
    }
    let Some(dir) = std::env::var_os("VOX_MUTANT_ENTRY_DIR").map(std::path::PathBuf::from) else {
        return entry;
    };
    let seq = entry.skeleton.seq;
    if let Some(adopted) = std::fs::read(dir.join(format!("adopt-{seq}")))
        .ok()
        .and_then(|bytes| Entry::from_wire(&bytes).ok())
        .filter(|adopted| {
            adopted.skeleton.author_id == entry.skeleton.author_id
                && adopted.skeleton.channel_id == entry.skeleton.channel_id
                && adopted.skeleton.seq == seq
        })
    {
        eprintln!("{MARKER}: appends the other copy's entry at {seq}");
        return adopted;
    }
    if let Err(error) = std::fs::write(dir.join(seq.to_string()), entry.to_wire()) {
        eprintln!("{MARKER}: cannot write its entry at {seq}: {error}");
    }
    entry
}

/// `strip-payload`: an ordinary body on the history path is answered as not held.
#[must_use]
pub fn strips_payload() -> bool {
    mode() == Mode::StripPayload
}

/// Whether what this build posts is a governance body bound to another epoch
/// (`author-misbound`): a consent grant signed with kind Governance whose body epoch is the
/// entry's own plus 7.
#[must_use]
pub fn misbound() -> bool {
    mode() == Mode::AuthorMisbound
}

/// The payload this build signs in place of `payload` when it posts: in
/// `author-unclassifiable`, bytes that are neither kind; otherwise `payload` itself.
#[must_use]
pub fn authored(payload: Vec<u8>) -> Vec<u8> {
    if mode() == Mode::AuthorUnclassifiable {
        b"VOX-MUTANT-SENDER: neither a governance body nor a sender-key message".to_vec()
    } else {
        payload
    }
}
