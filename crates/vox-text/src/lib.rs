//! Text another party wrote, made safe to print where a person or a model reads it (V210-123,
//! V210-154).
//!
//! An author's name in a room and a peer's connection-close reason are both chosen by someone
//! else and both end up on a terminal or in a model's context. A control character there starts a
//! line of its own, outside vox's framing, or drives the terminal; a bidi control reorders how the
//! rest of the line reads. Every printer of such text passes it through [`shown`].

pub mod fingerprint;
pub mod node;
pub mod offer;
pub mod read;

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
/// that could break or reorder it and every character a reader cannot see shown as an escape,
/// `⟨U+XXXX⟩` ([`reveal_keeping`], #331), and cut to `max` bytes with `…` (V210-123), never
/// inside an escape.
#[must_use]
pub fn shown(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max) + 3);
    for c in reveal_keeping(s, |_| false).chars() {
        if out.len() + c.len_utf8() > max {
            // An escape opened and not closed is cut whole.
            if let (Some(open), close) = (out.rfind(ESCAPE_OPEN), out.rfind(ESCAPE_CLOSE)) {
                if close.is_none_or(|c| c < open) {
                    out.truncate(open);
                }
            }
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Whether `c` is a character a reader cannot see but a model reads (#331): the invisible
/// carriers of a hidden instruction. The classes are those of a prompt-injection scanner's
/// "hidden Unicode" check: the zero-width characters and the soft hyphen (U+200B–U+200D, U+2060,
/// U+FEFF, U+00AD), every other Unicode format (Cf) character — the invisible operators
/// (U+2061–U+2064), the deprecated format controls (U+206A–U+206F), the interlinear annotation
/// marks (U+FFF9–U+FFFB), the Arabic, Syriac, Mongolian, Kaithi, Egyptian, shorthand and musical
/// format characters — the tag characters (U+E0000–U+E007F), which spell ASCII invisibly, and
/// the supplementary variation selectors (U+E0100–U+E01EF), which can carry bytes the same way.
/// The bidi controls and the directional marks are [`breaks_lines`]'s.
///
/// The emoji variation selectors (U+FE00–U+FE0F) are not hidden: they choose how a visible
/// character is drawn, and every emoji with U+FE0F needs them.
#[must_use]
pub fn hides(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

/// What opens a [`reveal`] escape. A literal one in the text is itself escaped, so every one a
/// reader sees was made by vox, and no text can forge an escape.
pub const ESCAPE_OPEN: char = '\u{27E8}';
/// What closes a [`reveal`] escape.
pub const ESCAPE_CLOSE: char = '\u{27E9}';

/// Whether `c` is drawn as an emoji (Extended_Pictographic, by its blocks): what a zero-width
/// joiner may stand between.
fn pictographic(c: char) -> bool {
    matches!(
        c,
        '\u{00A9}'
            | '\u{00AE}'
            | '\u{203C}'
            | '\u{2049}'
            | '\u{2122}'
            | '\u{2139}'
            | '\u{2194}'..='\u{21AA}'
            | '\u{231A}'..='\u{23FF}'
            | '\u{24C2}'
            | '\u{25AA}'..='\u{25FE}'
            | '\u{2600}'..='\u{27BF}'
            | '\u{2934}'..='\u{2935}'
            | '\u{2B05}'..='\u{2B55}'
            | '\u{3030}'
            | '\u{303D}'
            | '\u{3297}'
            | '\u{3299}'
            | '\u{1F000}'..='\u{1FAFF}'
            | '\u{1FC00}'..='\u{1FFFD}'
    )
}

/// What may follow an emoji before a joiner and still be the same emoji: the emoji presentation
/// selector and the skin tones.
fn emoji_modifier(c: char) -> bool {
    matches!(c, '\u{FE0F}' | '\u{1F3FB}'..='\u{1F3FF}')
}

/// The three subdivision flags (England, Scotland, Wales): a black flag, then tag characters,
/// then the cancel tag. The only tag characters a reader is shown as they are.
const SUBDIVISION_FLAGS: [&str; 3] = [
    "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
    "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
    "\u{1F3F4}\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}",
];

/// `s` with every character a reader cannot see ([`hides`]) shown as an escape, `⟨U+XXXX⟩`, so
/// text hidden from a person never reaches a model unseen (#331). A literal `⟨` is escaped too,
/// so an escape cannot be forged by typing one. A zero-width joiner stays where it joins two
/// emoji (👨‍👩‍👧, 🏳️‍🌈), and the three subdivision flags stay whole; everywhere else it is
/// escaped. Line breaks and the bidi controls are [`reveal_keeping`]'s.
#[must_use]
pub fn reveal(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1F3F4}' {
            if let Some(flag) = SUBDIVISION_FLAGS.iter().find(|f| {
                f.chars()
                    .eq(chars[i..].iter().copied().take(f.chars().count()))
            }) {
                out.push_str(flag);
                i += flag.chars().count();
                continue;
            }
        }
        let joins_emoji = c == '\u{200D}' && {
            let mut b = i;
            while b > 0 && emoji_modifier(chars[b - 1]) {
                b -= 1;
            }
            b > 0
                && pictographic(chars[b - 1])
                && chars.get(i + 1).is_some_and(|n| pictographic(*n))
        };
        if c == ESCAPE_OPEN || (hides(c) && !joins_emoji) {
            out.push_str(&escape(c));
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// `c` as a reader is shown it in place of itself: `⟨U+XXXX⟩`, the one style every printer of
/// room text uses (#331).
#[must_use]
pub fn escape(c: char) -> String {
    format!("{ESCAPE_OPEN}U+{:04X}{ESCAPE_CLOSE}", u32::from(c))
}

/// [`reveal`], and every character that could break or reorder a line ([`breaks_lines`]: the
/// controls, the line and paragraph separators, the bidi controls and directional marks) shown as
/// an [`escape`] too, except those `keep` says the caller lays out itself (a newline it indents, a
/// tab). **One style for everything hidden or line-breaking** (#331): before this, a bidi override
/// printed as `\u{202e}` in `vox room read`, as U+FFFD in the hook's drain and as itself in the
/// TUI, while a zero-width character printed as `⟨U+200B⟩` in all three.
#[must_use]
pub fn reveal_keeping(s: &str, keep: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in reveal(s).chars() {
        if breaks_lines(c) && !keep(c) {
            out.push_str(&escape(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` cut to at most `max` bytes, never inside a character or inside a [`reveal`] escape.
#[must_use]
pub fn cut_revealed(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let head = &s[..end];
    // An escape opened and not closed before the cut is cut whole.
    match (head.rfind(ESCAPE_OPEN), head.rfind(ESCAPE_CLOSE)) {
        (Some(open), close) if close.is_none_or(|c| c < open) => &s[..open],
        _ => head,
    }
}
