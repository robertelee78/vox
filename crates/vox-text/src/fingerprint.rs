//! A node's fingerprint as a person reads it (ADR-028 K-1, L-9): the whole 52-character base32
//! string in groups of four, with its **fingerprint art** beside it — a 5×5 mosaic of split
//! triangles derived from the fingerprint and from nothing else, so the same node draws the same
//! art on every run, in every client. The art is for recognition only: it is always shown beside
//! the text, never instead of it.

/// The four ways a cell of the art is split: the dark triangle in one corner.
const FACETS: [char; 4] = ['◢', '◣', '◤', '◥'];

/// The art's side, in cells.
pub const ART_SIDE: usize = 5;

/// `fingerprint` in groups of four characters, separated by spaces, for reading aloud or
/// comparing by eye: `k2m9 q7rt …`.
#[must_use]
pub fn grouped(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.trim().chars().collect();
    chars
        .chunks(4)
        .map(|g| g.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The fingerprint art of `fingerprint` (base32, as `vox id` prints it): [`ART_SIDE`] rows of
/// [`ART_SIDE`] cells, each cell two characters wide so it draws about square. Every bit of the
/// fingerprint moves the art: its 260 bits are folded into the 50 the cells use. `None` for text
/// that is not base32.
#[must_use]
pub fn art(fingerprint: &str) -> Option<Vec<String>> {
    let cells = ART_SIDE * ART_SIDE;
    let mut bits = vec![false; cells * 2];
    let mut at = 0usize;
    for c in fingerprint.trim().chars() {
        let v = base32_value(c)?;
        for shift in (0..5).rev() {
            let i = at % bits.len();
            bits[i] ^= (v >> shift) & 1 == 1;
            at += 1;
        }
    }
    if at == 0 {
        return None;
    }
    Some(
        (0..ART_SIDE)
            .map(|row| {
                (0..ART_SIDE)
                    .map(|col| {
                        let i = (row * ART_SIDE + col) * 2;
                        let facet = FACETS[usize::from(bits[i]) << 1 | usize::from(bits[i + 1])];
                        format!("{facet}{facet}")
                    })
                    .collect()
            })
            .collect(),
    )
}

/// The fingerprint as a card: its art, with the grouped text beside it, five groups to a line.
/// For text that is not base32, the grouped text alone.
#[must_use]
pub fn card(fingerprint: &str) -> Vec<String> {
    let text = grouped(fingerprint);
    let groups: Vec<&str> = text.split(' ').collect();
    let lines: Vec<String> = groups.chunks(5).map(|g| g.join(" ")).collect();
    let Some(art) = art(fingerprint) else {
        return lines;
    };
    art.into_iter()
        .enumerate()
        .map(|(i, row)| match lines.get(i) {
            Some(text) => format!("{row}  {text}"),
            None => row,
        })
        .collect()
}

fn base32_value(c: char) -> Option<u8> {
    match c.to_ascii_lowercase() {
        c @ 'a'..='z' => Some(c as u8 - b'a'),
        c @ '2'..='7' => Some(c as u8 - b'2' + 26),
        _ => None,
    }
}
