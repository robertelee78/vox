//! **An image share's preview** (ADR-028 F-9, #500): what a reader sees of a shared image while the
//! sharer is offline.
//!
//! The sharer's daemon, as it hashes a file it is to share, tries to read it as an image. When it
//! is one, the announcement carries its dimensions, a thumbnail and a BlurHash, inside the
//! encrypted message: the thumbnail is a JPEG of at most [`MAX_THUMB_BYTES`], so it fits a message
//! with room to spare (ADR-028's exception to "file bytes never enter the log", ADR-020 11.1). A
//! file that is not an image, or that cannot be decoded within [`limits`], gets no preview; the
//! share goes ahead without one.

use std::path::Path;

/// The most a thumbnail may hold (ADR-028 F-9): 16 KB.
pub const MAX_THUMB_BYTES: usize = 16 * 1024;

/// The longest edge a thumbnail starts at; it is halved until the JPEG fits.
const THUMB_EDGE: u32 = 320;

/// The smallest edge tried before giving up on a thumbnail.
const MIN_EDGE: u32 = 16;

/// JPEG qualities tried at each edge, best first.
const QUALITIES: [u8; 5] = [80, 65, 50, 35, 20];

/// BlurHash components across and down: enough for a photo's colour and light, few characters.
const BLUR_COMPONENTS: (u32, u32) = (4, 3);

/// What an image announcement carries of the image (ADR-028 F-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// The image's width, in pixels.
    pub width: u32,
    /// Its height, in pixels.
    pub height: u32,
    /// A JPEG of at most [`MAX_THUMB_BYTES`].
    pub thumb: Vec<u8>,
    /// Its BlurHash.
    pub blurhash: String,
}

impl Preview {
    /// As the announcement's `data.image` carries it.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        use base64::Engine as _;
        serde_json::json!({
            "width": self.width,
            "height": self.height,
            "thumb": base64::engine::general_purpose::STANDARD.encode(&self.thumb),
            "thumb_type": "image/jpeg",
            "blurhash": self.blurhash,
        })
    }
}

/// What a decode may cost: a share is anything a person picks, so a hostile or enormous file must
/// not take the daemon's memory with it.
fn limits() -> image::Limits {
    let mut l = image::Limits::default();
    l.max_image_width = Some(16_384);
    l.max_image_height = Some(16_384);
    l.max_alloc = Some(512 * 1024 * 1024);
    l
}

/// The preview of the file at `path`, or `None` when it is not an image this daemon reads.
#[must_use]
pub fn of_file(path: &Path) -> Option<Preview> {
    let mut reader = image::ImageReader::open(path)
        .ok()?
        .with_guessed_format()
        .ok()?;
    reader.format()?;
    reader.limits(limits());
    let img = reader.decode().ok()?;
    let (width, height) = (img.width(), img.height());
    let thumb = thumbnail(&img)?;
    let small = img.thumbnail(32, 32).to_rgba8();
    let blurhash = blurhash::encode(
        BLUR_COMPONENTS.0,
        BLUR_COMPONENTS.1,
        small.width(),
        small.height(),
        small.as_raw(),
    )
    .ok()?;
    Some(Preview {
        width,
        height,
        thumb,
        blurhash,
    })
}

/// A JPEG of `img` of at most [`MAX_THUMB_BYTES`]: the largest edge, and at it the best quality,
/// that fits.
fn thumbnail(img: &image::DynamicImage) -> Option<Vec<u8>> {
    let mut edge = THUMB_EDGE;
    while edge >= MIN_EDGE {
        let rgb = img.thumbnail(edge, edge).to_rgb8();
        for q in QUALITIES {
            let mut out = Vec::new();
            let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, q);
            if rgb.write_with_encoder(enc).is_ok() && out.len() <= MAX_THUMB_BYTES {
                return Some(out);
            }
        }
        edge /= 2;
    }
    None
}
