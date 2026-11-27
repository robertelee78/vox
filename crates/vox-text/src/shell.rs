//! A command Vox prints for a person or an agent to paste into a shell (v0.4.3): every argument
//! that a shell would read as anything but itself is put in single quotes, so the command does
//! what it says when pasted whole. A room link's `&` ran the rest of the line in the background
//! and cut the join off; a directory with a space split in two; `!` and `$` are expanded by zsh
//! and bash even inside double quotes, so the quotes are single, and an embedded `'` is written
//! `'\''`.
//!
//! **An argument holding a character a terminal acts on or a reader cannot see** (a control
//! character, a line or paragraph separator, a bidi control, a hidden character: a question's text
//! or a ref is the Session's own) is written as the output of POSIX `printf` over one single-quoted
//! format, `"$(printf '…')"`, in which only [`literal`] characters stand as themselves and every
//! other byte is a three-digit octal escape (`\047` for `'`, `\134` for `\`, `\045` for `%`,
//! `\342\200\213` for U+200B). Inside single quotes nothing is special to `sh`, dash, bash, zsh or
//! fish, and the format holds no `'`, so no byte the member chose can be read as syntax; the line
//! printed holds none of those characters; and `printf` gives the argument's bytes back. Two
//! limits. Command substitution drops every newline at the very end of its output, and no single
//! word puts them back in all of sh, dash, bash, zsh and fish (a sentinel needs `${x%…}` on a
//! variable set first: two statements, and fish has no `${…}`), so an argument ending in a newline
//! is refused: [`arg`] gives `None`, and [`command`] gives [`NO_PASTE`] in place of the command.
//! And fish before 3.4 does not know `"$(…)"` and refuses to parse the line, running nothing.
//!
//! One helper, used by every printer of a command (the CLI, the TUI, the agent hook and skill, and
//! the app through the FFI): never quoting written out by hand.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Whether `c` is read by every POSIX shell (and zsh) as itself, anywhere in a word: letters,
/// digits and `_ - . / : @ % + = ,`. `~` is not, since it expands at the start of a word.
fn plain(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '%' | '+' | '=' | ',')
}

/// Whether `c` may not be printed as itself even inside quotes: what could break or reorder the
/// line ([`crate::breaks_lines`]) or a reader cannot see ([`crate::hides`]).
fn unprintable(c: char) -> bool {
    crate::breaks_lines(c) || crate::hides(c)
}

/// Whether the byte `b` stands as itself in a `printf` format [`arg`] writes: ASCII letters and
/// digits, space, and `_ , . / : @ + =`. Not `%` or `\` (`printf` reads them), not `'` (it would
/// end the quotes), not `-` (a format that starts with it is an option), not `!` (bash's history
/// expansion reaches inside `"$(…)"`).
fn literal(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b' ' | b'_' | b',' | b'.' | b'/' | b':' | b'@' | b'+' | b'='
        )
}

/// What [`command`] gives in place of a command one of whose words ends in a newline: words, in
/// the place a caller prints the command, that say why there is none; pasted, they run nothing
/// a member chose.
pub const NO_PASTE: &str = "\u{27e8}no command to paste: a word of it ends in a line break, which \
                            a pasted command cannot carry\u{27e9}";

/// `arg` as one shell word that reads back as `arg` exactly: as it is when every character is
/// plain and it does not begin with `=`; when it holds an [`unprintable`] character,
/// `"$(printf '…')"`, each byte not [`literal`] as a three-digit octal escape; else in single
/// quotes, each `'` in it written `'\''`. An empty argument is `''`. A word beginning with `=` is
/// zsh's `=command` expansion (a share named `=eq.txt` became "eq.txt not found"), so it is quoted
/// though `=` is plain inside a word. `None` for an argument ending in a newline, which no pasted
/// word carries whole: the caller says so instead of printing a command.
#[must_use]
pub fn arg(arg: &str) -> Option<Cow<'_, str>> {
    if arg.ends_with('\n') {
        return None;
    }
    if !arg.is_empty() && !arg.starts_with('=') && arg.chars().all(plain) {
        return Some(Cow::Borrowed(arg));
    }
    let mut out = String::with_capacity(arg.len() + 3);
    if arg.chars().any(unprintable) {
        out.push_str("\"$(printf '");
        for b in arg.bytes() {
            if literal(b) {
                out.push(char::from(b));
            } else {
                let _ = write!(out, "\\{b:03o}");
            }
        }
        out.push_str("')\"");
        return Some(Cow::Owned(out));
    }
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Some(Cow::Owned(out))
}

/// `words` as one command line to paste: each word through [`arg`], joined by spaces; [`NO_PASTE`]
/// when a word ends in a newline.
#[must_use]
pub fn command<S: AsRef<str>>(words: &[S]) -> String {
    words
        .iter()
        .map(|w| arg(w.as_ref()))
        .collect::<Option<Vec<_>>>()
        .map_or_else(|| NO_PASTE.to_owned(), |words| words.join(" "))
}

/// A node-scoped command carries its acting node into the operator's other terminal.
#[must_use]
pub fn node_command<S: AsRef<str>>(words: &[S], node: &str) -> String {
    let mut words: Vec<String> = words.iter().map(|w| w.as_ref().to_owned()).collect();
    // A legal node name may start with `-`; an option's attached value stays a value.
    if node.starts_with('-') {
        words.push(format!("--node={node}"));
    } else {
        words.extend(["--node".to_owned(), node.to_owned()]);
    }
    command(&words)
}
