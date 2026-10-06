//! **Images drawn inline in the timeline** (ADR-028 F-11, #502): kitty, iTerm2, sixel, then
//! half-blocks, and only an image whose copy on this node was verified (see
//! `live::DaemonCore::check_pulls`).
//!
//! The protocol is chosen from what the terminal declares in the environment, never by asking it:
//! a query an old terminal or a pty does not answer would stall the TUI. Half-blocks colour each
//! cell, so they are drawn only on a terminal that declares true colour; elsewhere a verified image
//! is named in words, as an unverified one is.

use std::collections::HashMap;
use std::path::Path;

use image::DynamicImage;

use ratatui::layout::Rect;
use ratatui::Frame;
use ratatui_image::picker::{Picker, ProtocolType};
use ratatui_image::protocol::Protocol;
use ratatui_image::{Image, Resize};
use vox_core::hash::Digest32;

/// The rows a drawn image takes in the timeline.
pub const IMAGE_ROWS: u16 = 10;

/// The longest edge an image is kept at once decoded: more than the timeline's rows ever show.
pub const DECODED_EDGE: u32 = 1024;

/// The cell size assumed when the terminal is not asked: a common monospace font's.
const FONT_SIZE: (u16, u16) = (10, 20);

/// **Verify and decode a pulled copy, off the TUI's thread** (ADR-028 F-11): its size and
/// SHA-256 against the announcement's, read in pieces; then decoded within the limits the sharer's
/// daemon decodes with (`vox_core::node::preview::decode`), and scaled to at most
/// [`DECODED_EDGE`]. A copy that is not what was announced stays unverified; one past the limits
/// is said, never drawn.
#[must_use]
pub fn verify_and_decode(path: &Path, size: u64, sha256: &str) -> crate::viewmodel::ImageState {
    use crate::viewmodel::ImageState;
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return ImageState::Unverified;
    };
    let (mut hasher, mut seen, mut buf) = (Sha256::new(), 0u64, vec![0u8; 64 * 1024]);
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                seen += n as u64;
                if seen > size {
                    return ImageState::Unverified;
                }
                hasher.update(&buf[..n]);
            }
            Err(_) => return ImageState::Unverified,
        }
    }
    let got: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if seen != size || !got.eq_ignore_ascii_case(sha256) {
        return ImageState::Unverified;
    }
    match vox_core::node::preview::decode(path) {
        Some(img) if img.width() > DECODED_EDGE || img.height() > DECODED_EDGE => {
            ImageState::Ready(std::sync::Arc::new(
                img.thumbnail(DECODED_EDGE, DECODED_EDGE),
            ))
        }
        Some(img) => ImageState::Ready(std::sync::Arc::new(img)),
        None => ImageState::NotDrawn(PAST_LIMITS),
    }
}

/// Said of a verified image this TUI does not decode: one past its limits, or not an image.
pub const PAST_LIMITS: &str = "verified; not drawn: past what this TUI decodes";

/// How the terminal draws images, by what it declares (`TERM`, `TERM_PROGRAM`, `LC_TERMINAL`,
/// `KITTY_WINDOW_ID`, `COLORTERM`, `NO_COLOR`), or `None` when it draws none.
#[must_use]
pub fn protocol_from(var: impl Fn(&str) -> Option<String>) -> Option<ProtocolType> {
    let term = var("TERM").unwrap_or_default().to_ascii_lowercase();
    let program = var("TERM_PROGRAM").unwrap_or_default();
    if term.contains("kitty") || var("KITTY_WINDOW_ID").is_some() || term.contains("ghostty") {
        Some(ProtocolType::Kitty)
    } else if program == "iTerm.app"
        || program == "WezTerm"
        || var("LC_TERMINAL").is_some_and(|t| t == "iTerm2")
    {
        Some(ProtocolType::Iterm2)
    } else if term.contains("sixel") || term.starts_with("foot") || term.contains("mlterm") {
        Some(ProtocolType::Sixel)
    } else if crate::theme::depth_from(
        var("NO_COLOR").as_deref(),
        var("COLORTERM").as_deref(),
        Some(&term),
    ) == crate::theme::Depth::TrueColor
    {
        Some(ProtocolType::Halfblocks)
    } else {
        None
    }
}

/// The images this TUI has made ready to draw, by entry and width, and how it draws them.
pub struct Images {
    picker: Option<Picker>,
    drawn: HashMap<(Digest32, u16), Option<Protocol>>,
}

impl std::fmt::Debug for Images {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Images")
            .field("protocol", &self.picker.map(Picker::protocol_type))
            .field("ready", &self.drawn.len())
            .finish()
    }
}

impl Default for Images {
    fn default() -> Self {
        let picker = protocol_from(|k| std::env::var(k).ok().filter(|v| !v.is_empty())).map(|p| {
            let mut picker = Picker::from_fontsize(FONT_SIZE);
            picker.set_protocol_type(p);
            picker
        });
        Self {
            picker,
            drawn: HashMap::new(),
        }
    }
}

impl Images {
    /// Whether this terminal draws images at all.
    #[must_use]
    pub fn draws(&self) -> bool {
        self.picker.is_some()
    }

    /// Draw `img`, the verified and decoded image shared by `entry`, into `area`: fitted once per
    /// width, from an image already scaled to at most [`DECODED_EDGE`].
    pub fn draw(&mut self, frame: &mut Frame, area: Rect, entry: Digest32, img: &DynamicImage) {
        let Some(picker) = self.picker else {
            return;
        };
        let proto = self.drawn.entry((entry, area.width)).or_insert_with(|| {
            picker
                .new_protocol(
                    img.clone(),
                    Rect::new(0, 0, area.width, area.height),
                    Resize::Fit(None),
                )
                .ok()
        });
        if let Some(p) = proto {
            frame.render_widget(Image::new(p), area);
        }
    }
}
