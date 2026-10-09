//! An alias as a person reads it (ADR-028 K-4), one rule for every client: the TUI, the CLI and
//! the macOS app (through the FFI).

/// How many fingerprint characters follow an alias that another node's alias equals but for case.
pub const CLASH_SUFFIX: usize = 6;

/// `who`'s alias as a person reads it: the alias, and, when another node in `entries` has the
/// same alias but for case ("Ann" and "ann"), `#` and the first [`CLASH_SUFFIX`] characters of its
/// fingerprint (`fingerprint` gives it, base32), so the two are never taken for one. `None` when
/// `who` has no alias in `entries`.
#[must_use]
pub fn alias_of<K: PartialEq>(
    entries: &[(K, String)],
    who: &K,
    fingerprint: impl FnOnce(&K) -> String,
) -> Option<String> {
    let (_, alias) = entries.iter().find(|(id, _)| id == who)?;
    let alias = alias.trim();
    if alias.is_empty() {
        return None;
    }
    Some(if clashes(entries, who, alias) {
        let suffix: String = fingerprint(who).chars().take(CLASH_SUFFIX).collect();
        format!("{alias}#{suffix}")
    } else {
        alias.to_owned()
    })
}

/// Whether `alias` would be taken for another node's in `entries` (the same but for case, ADR-028
/// K-4), other than `who`'s own: what the forms that add, rename or accept a node warn of.
#[must_use]
pub fn clashes<K: PartialEq>(entries: &[(K, String)], who: &K, alias: &str) -> bool {
    let alias = alias.trim().to_lowercase();
    !alias.is_empty()
        && entries
            .iter()
            .any(|(id, other)| id != who && other.trim().to_lowercase() == alias)
}
