//! A command Vox prints for a person or an agent to paste into a shell (v0.4.3): every argument
//! that a shell would read as anything but itself is put in single quotes, so the command does
//! what it says when pasted whole. A room link's `&` ran the rest of the line in the background
//! and cut the join off; a directory with a space split in two; `!` and `$` are expanded by zsh
//! and bash even inside double quotes, so the quotes are single, and an embedded `'` is written
//! `'\''`.
//!
//! One helper, used by every printer of a command (the CLI, the TUI, the agent hook and skill, and
//! the app through the FFI): never quoting written out by hand.

use std::borrow::Cow;

/// Whether `c` is read by every POSIX shell (and zsh) as itself, anywhere in a word: letters,
/// digits and `_ - . / : @ % + = ,`. `~` is not, since it expands at the start of a word.
fn plain(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '%' | '+' | '=' | ',')
}

/// `arg` as one shell word that reads back as `arg` exactly: as it is when every character is
/// plain, else in single quotes, each `'` in it written `'\''`; an empty argument is `''`.
#[must_use]
pub fn arg(arg: &str) -> Cow<'_, str> {
    if !arg.is_empty() && arg.chars().all(plain) {
        return Cow::Borrowed(arg);
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Cow::Owned(out)
}

/// `words` as one command line to paste: each word through [`arg`], joined by spaces.
#[must_use]
pub fn command<S: AsRef<str>>(words: &[S]) -> String {
    words
        .iter()
        .map(|w| arg(w.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}
