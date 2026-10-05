//! The look's one token file (ADR-028 L-1, L-2): read, checked, and written out for each client.
//!
//! `assets/theme/vox-tokens.json` is the only place a colour, a typeface or a motion value is
//! defined. The TUI's build script turns it into Rust constants ([`rust_source`]); `vox-theme
//! swift` turns it into the macOS app's asset catalogue and a Swift file ([`write_swift`]). A file
//! that is not exactly what this reader expects is refused with the reason, never half-read.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Map, Value};

/// The only schema this reader takes.
pub const SCHEMA: &str = "vox-tokens/1";

/// The colours ADR-028 L-2 names. Each MUST be in the file, and the file MUST hold no other.
pub const COLORS: &[&str] = &[
    "bg.base",
    "bg.raised",
    "bg.panel",
    "bg.overlay",
    "line.hair",
    "text.primary",
    "text.secondary",
    "text.muted",
    "accent",
    "accent.hover",
    "accent.deep",
    "attention",
    "danger",
];

/// Where a colour falls back to in a 16-colour terminal: one of the terminal's own slots, or its
/// default foreground or background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ansi16 {
    DefaultFg,
    DefaultBg,
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
}

impl Ansi16 {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "default-fg" => Self::DefaultFg,
            "default-bg" => Self::DefaultBg,
            "black" => Self::Black,
            "red" => Self::Red,
            "green" => Self::Green,
            "yellow" => Self::Yellow,
            "blue" => Self::Blue,
            "magenta" => Self::Magenta,
            "cyan" => Self::Cyan,
            "white" => Self::White,
            "bright-black" => Self::BrightBlack,
            "bright-red" => Self::BrightRed,
            "bright-green" => Self::BrightGreen,
            "bright-yellow" => Self::BrightYellow,
            "bright-blue" => Self::BrightBlue,
            "bright-magenta" => Self::BrightMagenta,
            "bright-cyan" => Self::BrightCyan,
            "bright-white" => Self::BrightWhite,
            _ => return None,
        })
    }

    /// The variant's name, as the generated Rust names it.
    #[must_use]
    pub fn rust(self) -> &'static str {
        match self {
            Self::DefaultFg => "DefaultFg",
            Self::DefaultBg => "DefaultBg",
            Self::Black => "Black",
            Self::Red => "Red",
            Self::Green => "Green",
            Self::Yellow => "Yellow",
            Self::Blue => "Blue",
            Self::Magenta => "Magenta",
            Self::Cyan => "Cyan",
            Self::White => "White",
            Self::BrightBlack => "BrightBlack",
            Self::BrightRed => "BrightRed",
            Self::BrightGreen => "BrightGreen",
            Self::BrightYellow => "BrightYellow",
            Self::BrightBlue => "BrightBlue",
            Self::BrightMagenta => "BrightMagenta",
            Self::BrightCyan => "BrightCyan",
            Self::BrightWhite => "BrightWhite",
        }
    }
}

/// One colour token.
#[derive(Debug, Clone)]
pub struct Color {
    pub name: String,
    pub rgb: [u8; 3],
    pub xterm256: u8,
    pub ansi16: Ansi16,
}

/// One typeface token, for the app (the TUI draws in the terminal's own font).
#[derive(Debug, Clone)]
pub struct Font {
    pub name: String,
    pub family: String,
    /// The system font role (`body`, `monospaced`), when the face is the system's.
    pub system: Option<String>,
    /// The bundled font file, when the face is not the system's.
    pub bundled: Option<String>,
    pub weight: u16,
    pub tracking: f64,
    pub uppercase: bool,
    pub size: Option<f64>,
}

/// Every token in the file.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub colors: Vec<Color>,
    pub fonts: Vec<Font>,
    /// Motion values, by name: frame counts, milliseconds, damping.
    pub motion: Vec<(String, f64)>,
}

impl Tokens {
    /// The colour of this name, which [`parse`] has made sure exists for every name in [`COLORS`].
    #[must_use]
    pub fn color(&self, name: &str) -> Option<&Color> {
        self.colors.iter().find(|c| c.name == name)
    }
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{what} is not an object"))
}

fn hex(s: &str, what: &str) -> Result<[u8; 3], String> {
    let b = s.as_bytes();
    if b.len() != 7 || b[0] != b'#' || !s[1..].bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{what}: {s:?} is not a #rrggbb colour"));
    }
    let byte = |i: usize| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("{what}: {e}"));
    Ok([byte(1)?, byte(3)?, byte(5)?])
}

/// Read and check the token file's text.
///
/// # Errors
/// The first thing wrong with it, in words: a wrong schema, a theme that is not `dark`, a colour
/// missing, unknown or malformed, a type or motion value of the wrong kind.
pub fn parse(text: &str) -> Result<Tokens, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let root = object(&root, "the token file")?;
    match root.get("schema").and_then(Value::as_str) {
        Some(SCHEMA) => {}
        other => return Err(format!("schema is {other:?}, not {SCHEMA:?}")),
    }
    if root.get("theme").and_then(Value::as_str) != Some("dark") {
        return Err("theme must be \"dark\", the only theme (ADR-028 L-2)".into());
    }

    let mut colors = Vec::new();
    let table = object(root.get("color").unwrap_or(&Value::Null), "color")?;
    for (name, v) in table {
        if !COLORS.contains(&name.as_str()) {
            return Err(format!("color {name:?} is not one ADR-028 L-2 names"));
        }
        let v = object(v, &format!("color {name:?}"))?;
        let rgb = hex(
            v.get("hex").and_then(Value::as_str).unwrap_or(""),
            &format!("color {name:?}"),
        )?;
        let xterm256 = v
            .get("xterm256")
            .and_then(Value::as_u64)
            .filter(|n| (16..=255).contains(n))
            .ok_or_else(|| format!("color {name:?}: xterm256 must be an index from 16 to 255"))?;
        let ansi = v.get("ansi16").and_then(Value::as_str).unwrap_or("");
        let ansi16 = Ansi16::parse(ansi)
            .ok_or_else(|| format!("color {name:?}: ansi16 {ansi:?} is not a 16-colour slot"))?;
        colors.push(Color {
            name: name.clone(),
            rgb,
            xterm256: u8::try_from(xterm256).map_err(|e| e.to_string())?,
            ansi16,
        });
    }
    for name in COLORS {
        if !colors.iter().any(|c| c.name == *name) {
            return Err(format!("color {name:?} is missing (ADR-028 L-2)"));
        }
    }

    let mut fonts = Vec::new();
    for (name, v) in object(root.get("type").unwrap_or(&Value::Null), "type")? {
        let v = object(v, &format!("type {name:?}"))?;
        let family = v
            .get("family")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("type {name:?} has no family"))?;
        let weight = v
            .get("weight")
            .and_then(Value::as_u64)
            .filter(|w| (100..=900).contains(w))
            .ok_or_else(|| format!("type {name:?}: weight must be 100 to 900"))?;
        let system = v.get("system").and_then(Value::as_str).map(str::to_owned);
        let bundled = v.get("bundled").and_then(Value::as_str).map(str::to_owned);
        if system.is_some() == bundled.is_some() {
            return Err(format!(
                "type {name:?} must be either a system font or a bundled one"
            ));
        }
        fonts.push(Font {
            name: name.clone(),
            family: family.to_owned(),
            system,
            bundled,
            weight: u16::try_from(weight).map_err(|e| e.to_string())?,
            tracking: v.get("tracking").and_then(Value::as_f64).unwrap_or(0.0),
            uppercase: v.get("uppercase").and_then(Value::as_bool).unwrap_or(false),
            size: v.get("size").and_then(Value::as_f64),
        });
    }

    let mut motion = Vec::new();
    for (name, v) in object(root.get("motion").unwrap_or(&Value::Null), "motion")? {
        let n = v
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or_else(|| format!("motion {name:?} must be a number of at least 0"))?;
        motion.push((name.clone(), n));
    }
    Ok(Tokens {
        colors,
        fonts,
        motion,
    })
}

/// Read and check the token file at `path`.
///
/// # Errors
/// The file could not be read, or [`parse`] refused it; the message names the path.
pub fn load(path: &Path) -> Result<Tokens, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `bg.base` → `BG_BASE`.
fn upper_snake(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// `bg.base` → `BgBase`; `bg.base` with `lower` → `bgBase`.
fn camel(name: &str, lower: bool) -> String {
    let mut out = String::new();
    for (i, part) in name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
        .enumerate()
    {
        let mut cs = part.chars();
        if let Some(first) = cs.next() {
            if i == 0 && lower {
                out.push(first.to_ascii_lowercase());
            } else {
                out.push(first.to_ascii_uppercase());
            }
            out.extend(cs);
        }
    }
    out
}

/// The TUI's constants: one `Token` per colour and one constant per motion value. The types they
/// name (`Token`, `Ansi16`) are the TUI's own (`vox-tui`'s `theme` module).
#[must_use]
pub fn rust_source(t: &Tokens) -> String {
    let mut s = String::from(
        "// Generated from assets/theme/vox-tokens.json by vox-tui's build script. Do not edit.\n",
    );
    for c in &t.colors {
        let [r, g, b] = c.rgb;
        let _ = writeln!(
            s,
            "pub const {}: Token = Token {{ rgb: (0x{r:02x}, 0x{g:02x}, 0x{b:02x}), xterm256: {}, ansi16: Ansi16::{} }};",
            upper_snake(&c.name),
            c.xterm256,
            c.ansi16.rust()
        );
    }
    for (name, n) in &t.motion {
        let _ = writeln!(s, "pub const {}: f64 = {n:?};", upper_snake(name));
    }
    s
}

/// Write the macOS app's tokens into `out`: an asset catalogue `VoxTokens.xcassets` with one
/// colour set per colour, and `VoxTokens.swift` naming every colour, typeface and motion value.
///
/// # Errors
/// A directory or file could not be written.
pub fn write_swift(t: &Tokens, out: &Path) -> std::io::Result<()> {
    let catalog = out.join("VoxTokens.xcassets");
    std::fs::create_dir_all(&catalog)?;
    std::fs::write(
        catalog.join("Contents.json"),
        "{\n  \"info\" : { \"author\" : \"vox-theme\", \"version\" : 1 }\n}\n",
    )?;
    let mut swift = String::from(
        "// Generated from assets/theme/vox-tokens.json by `vox-theme swift`. Do not edit.\nimport SwiftUI\n\npublic enum VoxTokens {\n    public enum Colors {\n",
    );
    for c in &t.colors {
        let set = catalog.join(format!("{}.colorset", camel(&c.name, false)));
        std::fs::create_dir_all(&set)?;
        let [r, g, b] = c.rgb;
        std::fs::write(
            set.join("Contents.json"),
            format!(
                "{{\n  \"colors\" : [ {{ \"idiom\" : \"universal\", \"color\" : {{ \"color-space\" : \"srgb\", \"components\" : {{ \"red\" : \"0x{r:02X}\", \"green\" : \"0x{g:02X}\", \"blue\" : \"0x{b:02X}\", \"alpha\" : \"1.000\" }} }} }} ],\n  \"info\" : {{ \"author\" : \"vox-theme\", \"version\" : 1 }}\n}}\n"
            ),
        )?;
        let _ = writeln!(
            swift,
            "        public static let {} = Color(\"{}\")",
            camel(&c.name, true),
            camel(&c.name, false)
        );
    }
    swift.push_str("    }\n\n    public struct Face { public let family: String; public let system: String?; public let bundled: String?; public let weight: Int; public let tracking: Double; public let uppercase: Bool; public let size: Double? }\n\n    public enum Fonts {\n");
    for f in &t.fonts {
        let opt = |o: &Option<String>| o.as_ref().map_or("nil".to_owned(), |s| format!("{s:?}"));
        let _ = writeln!(
            swift,
            "        public static let {} = Face(family: {:?}, system: {}, bundled: {}, weight: {}, tracking: {:?}, uppercase: {}, size: {})",
            camel(&f.name, true),
            f.family,
            opt(&f.system),
            opt(&f.bundled),
            f.weight,
            f.tracking,
            f.uppercase,
            f.size.map_or("nil".to_owned(), |n| format!("{n:?}"))
        );
    }
    swift.push_str("    }\n\n    public enum Motion {\n");
    for (name, n) in &t.motion {
        let _ = writeln!(
            swift,
            "        public static let {}: Double = {n:?}",
            camel(name, true)
        );
    }
    swift.push_str("    }\n}\n");
    std::fs::write(out.join("VoxTokens.swift"), swift)
}
