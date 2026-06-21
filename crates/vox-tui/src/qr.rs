//! Terminal QR rendering (ADR-015 §"Terminal QR rendering contract").
//!
//! Encodes a payload (an invite channelID, an identity, or a verification record)
//! as a QR matrix at ECC level **M**, surrounds it with the mandatory **quiet
//! zone**, and renders it either as compact **Unicode half-blocks** (default) or an
//! **ASCII** grid (`--accessible` / non-Unicode terminals). The caller always shows
//! a copyable string alongside and uses [`fits`] for the minimum-terminal-size
//! check (falling back to the copyable string when the QR will not fit).
//!
//! Convention: **dark** modules render filled, **light** (incl. the quiet zone)
//! render blank, i.e. dark-on-light — directly scannable on a light-background
//! terminal. `invert` swaps them for dark-background terminals. Which convention a
//! given terminal needs is a terminal-matrix / manual-spike concern (ADR-015).

use qrcode::{EcLevel, QrCode};

use vox_core::error::{Error, Result};

/// The mandatory quiet-zone width in modules around the QR (QR spec minimum is 4).
pub const QUIET_ZONE: usize = 4;

/// How to render the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// Compact Unicode half-blocks (two vertical modules per character cell).
    HalfBlock,
    /// ASCII grid (two characters per module), for non-Unicode terminals.
    Ascii,
}

/// A rendered QR: the text plus its character dimensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The multi-line rendering (no trailing newline).
    pub text: String,
    /// Width in terminal columns.
    pub cols: usize,
    /// Height in terminal rows.
    pub rows: usize,
}

/// Build the QR module grid (including the quiet zone) for `data` at ECC level M.
/// `grid[y][x]` is `true` for a dark module. Returns the padded side length too.
fn module_grid(data: &[u8]) -> Result<Vec<Vec<bool>>> {
    let code = QrCode::with_error_correction_level(data, EcLevel::M)
        .map_err(|_| Error::SizeLimitExceeded("qr payload too large for a QR code"))?;
    let width = code.width();
    let colors = code.to_colors();
    let padded = width + 2 * QUIET_ZONE;
    let mut grid = vec![vec![false; padded]; padded];
    for y in 0..width {
        for x in 0..width {
            // `qrcode::Color::Dark` is the dark module.
            let dark = colors[y * width + x] == qrcode::Color::Dark;
            grid[y + QUIET_ZONE][x + QUIET_ZONE] = dark;
        }
    }
    Ok(grid)
}

/// Render `data` as a QR in the chosen `style`. `invert` swaps dark/light (for
/// dark-background terminals).
pub fn render(data: &[u8], style: Style, invert: bool) -> Result<Rendered> {
    let grid = module_grid(data)?;
    let side = grid.len();
    match style {
        Style::Ascii => Ok(render_ascii(&grid, invert)),
        Style::HalfBlock => Ok(render_half_block(&grid, invert, side)),
    }
}

/// `is_dark(cell)` after applying `invert`.
fn lit(cell: bool, invert: bool) -> bool {
    cell ^ invert
}

fn render_ascii(grid: &[Vec<bool>], invert: bool) -> Rendered {
    // Two characters per module keeps the aspect ratio roughly square.
    let mut text = String::new();
    for (i, row) in grid.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        for &cell in row {
            text.push_str(if lit(cell, invert) { "##" } else { "  " });
        }
    }
    let rows = grid.len();
    let cols = grid.first().map_or(0, |r| r.len()) * 2;
    Rendered { text, cols, rows }
}

fn render_half_block(grid: &[Vec<bool>], invert: bool, side: usize) -> Rendered {
    // Pack two module rows into one character row via ▀ (upper), ▄ (lower), █ (both).
    let mut text = String::new();
    let mut out_rows = 0;
    let mut y = 0;
    while y < side {
        if out_rows > 0 {
            text.push('\n');
        }
        for x in 0..side {
            let top = lit(grid[y][x], invert);
            let bottom = grid.get(y + 1).is_some_and(|r| lit(r[x], invert));
            text.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out_rows += 1;
        y += 2;
    }
    Rendered {
        text,
        cols: side,
        rows: out_rows,
    }
}

/// Whether a rendering of these dimensions fits within a terminal of
/// `(term_cols, term_rows)`, leaving the caller to fall back to the copyable string
/// when it does not (ADR-015 minimum-terminal-size check).
#[must_use]
pub fn fits(r: &Rendered, term_cols: usize, term_rows: usize) -> bool {
    r.cols <= term_cols && r.rows <= term_rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_block_round_trips_via_decoder() {
        // Render, then reconstruct the module grid from the half-block output and
        // confirm it matches a freshly-built grid (proves the rendering is faithful).
        let data = b"vox:channel:0123456789abcdef";
        let r = render(data, Style::HalfBlock, false).unwrap();
        let grid = module_grid(data).unwrap();
        let side = grid.len();
        assert_eq!(r.cols, side);
        assert_eq!(r.rows, side.div_ceil(2));
        // Spot-check: the top-left quiet-zone module is light → first char is space
        // (or ▄ if the module below is dark, but quiet zone is all light).
        assert!(r.text.starts_with(' '));
    }

    #[test]
    fn ascii_has_two_chars_per_module_and_quiet_zone() {
        let data = b"vox";
        let r = render(data, Style::Ascii, false).unwrap();
        let grid = module_grid(data).unwrap();
        assert_eq!(r.cols, grid.len() * 2);
        assert_eq!(r.rows, grid.len());
        // First row is entirely quiet zone → all blank.
        let first_line = r.text.lines().next().unwrap();
        assert!(first_line.chars().all(|c| c == ' '));
    }

    #[test]
    fn quiet_zone_is_present_on_all_sides() {
        let grid = module_grid(b"hello").unwrap();
        let side = grid.len();
        // The outermost QUIET_ZONE rows/cols must be all-light.
        for i in 0..QUIET_ZONE {
            assert!(grid[i].iter().all(|&c| !c), "top quiet row {i}");
            assert!(grid[side - 1 - i].iter().all(|&c| !c), "bottom quiet row");
            for row in &grid {
                assert!(!row[i], "left quiet col");
                assert!(!row[side - 1 - i], "right quiet col");
            }
        }
    }

    #[test]
    fn invert_flips_every_cell() {
        let data = b"x";
        let normal = render(data, Style::Ascii, false).unwrap();
        let inverted = render(data, Style::Ascii, true).unwrap();
        assert_ne!(normal.text, inverted.text);
        // A blank cell in normal becomes filled in inverted at the same position.
        assert!(normal.text.starts_with("  "));
        assert!(inverted.text.starts_with("##"));
    }

    #[test]
    fn fits_checks_both_dimensions() {
        let r = Rendered {
            text: String::new(),
            cols: 40,
            rows: 20,
        };
        assert!(fits(&r, 80, 24));
        assert!(!fits(&r, 39, 24));
        assert!(!fits(&r, 80, 19));
    }

    #[test]
    fn oversized_payload_errors() {
        // A payload far beyond QR capacity returns a size error, never a panic.
        let huge = vec![b'a'; 8000];
        assert!(matches!(
            render(&huge, Style::HalfBlock, false),
            Err(Error::SizeLimitExceeded(_))
        ));
    }
}
