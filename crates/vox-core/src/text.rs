//! Text a peer chose, made safe to print (V210-154).
//!
//! A peer can put any bytes in what it sends back: a QUIC connection-close reason is the one that
//! reached a terminal raw, and its `Display` in quinn is `String::from_utf8_lossy` of whatever the
//! peer wrote. An escape sequence there drives the operator's terminal; a line break there forges
//! a line of vox's own output.
//!
//! [`breaks_lines`] and [`shown`] are the same rule as `vox_agentcomms::envelope`'s, which
//! sanitises what room members write (V210-123). The core cannot depend on that crate (it sits
//! above the core), so the rule is kept here too; the two must stay the same.

/// Whether `c` may not be printed as it is: every control character (which includes `\n`, `\r`,
/// VT, FF, NEL, ESC and NUL), the Unicode line and paragraph separators, and the bidirectional
/// controls (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F), which reorder how a line displays.
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

/// `s` as it may be printed: on one line, every character [`breaks_lines`] refuses replaced with
/// U+FFFD, and cut to `max` bytes with `…`.
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

/// The most bytes of a peer's close reason that are printed.
pub const PEER_REASON_MAX: usize = 160;

/// A QUIC connection error as vox prints it, with **the peer's reason shown, never raw**.
///
/// quinn's own `Display` writes a peer's CONNECTION_CLOSE or APPLICATION_CLOSE reason verbatim.
/// Every other kind of `ConnectionError` is this endpoint's own text and is kept as quinn says it.
#[must_use]
pub fn peer_error(e: &quinn::ConnectionError) -> String {
    use quinn::ConnectionError as C;
    let reason = |r: &[u8]| shown(&String::from_utf8_lossy(r), PEER_REASON_MAX);
    match e {
        C::ConnectionClosed(c) if c.reason.is_empty() => {
            format!("the peer aborted the connection: {}", c.error_code)
        }
        C::ConnectionClosed(c) => format!(
            "the peer aborted the connection: {}: \"{}\"",
            c.error_code,
            reason(&c.reason)
        ),
        C::ApplicationClosed(a) if a.reason.is_empty() => {
            format!("the peer closed the connection (code {})", a.error_code)
        }
        C::ApplicationClosed(a) => format!(
            "the peer closed the connection (code {}): \"{}\"",
            a.error_code,
            reason(&a.reason)
        ),
        other => other.to_string(),
    }
}
