//! Text another party wrote, made safe to print where a person or a model reads it (V210-123,
//! V210-154).
//!
//! An author's name in a room and a peer's connection-close reason are both chosen by someone
//! else and both end up on a terminal or in a model's context. A control character there starts a
//! line of its own, outside vox's framing, or drives the terminal; a bidi control reorders how the
//! rest of the line reads. Every printer of such text passes it through [`shown`].

/// Whether `c` may not appear in text printed for somebody reading (V210-123): every control
/// character (which includes `\n`, `\r`, VT, FF, NEL, ESC and NUL), the Unicode line and
/// paragraph separators, and the bidirectional controls — embeddings and overrides
/// (U+202A–U+202E), isolates (U+2066–U+2069) and the directional marks (U+200E, U+200F).
///
/// The bidi controls start no line, but in a terminal or an editor they reorder how the rest of
/// one displays, so a name could make a board row read as something it does not say.
#[must_use]
pub fn breaks_lines(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200E}'
                | '\u{200F}'
        )
}

/// `s` as it may be printed where a person or a model reads it: on one line, every character
/// that could break it replaced with U+FFFD, and cut to `max` bytes with `…` (V210-123).
#[must_use]
pub fn shown(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max) + 3);
    for c in s.chars() {
        let c = if breaks_lines(c) { '\u{fffd}' } else { c };
        if out.len() + c.len_utf8() > max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}
