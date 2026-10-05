//! The TUI's colours, from the one token file (ADR-028 L-1, L-2, L-5).
//!
//! Every colour the TUI draws is a [`Token`] generated at build time from
//! `assets/theme/vox-tokens.json`; no other module names a colour. How a token is drawn depends on
//! what the terminal can show, decided once per process ([`depth`]): truecolour when `COLORTERM`
//! says so, the xterm 256-colour index when `TERM` names a 256-colour terminal, the token's
//! 16-colour slot otherwise, and no colour at all under `NO_COLOR` or a `dumb` terminal. With no
//! colour, every state still reads by its glyph and its word (ADR-028 E-6).

use std::sync::OnceLock;

use ratatui::style::{Color, Style};

/// Where a token falls back to in a 16-colour terminal.
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

/// One colour token: its truecolour value and its two fallbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub rgb: (u8, u8, u8),
    pub xterm256: u8,
    pub ansi16: Ansi16,
}

include!(concat!(env!("OUT_DIR"), "/theme_tokens.rs"));

/// What the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// `NO_COLOR`, or a `dumb` terminal: draw no colour.
    None,
    Ansi16,
    Xterm256,
    TrueColor,
}

/// Decide [`Depth`] from the environment, as a person's terminal declares it.
#[must_use]
pub fn depth_from(no_color: Option<&str>, colorterm: Option<&str>, term: Option<&str>) -> Depth {
    if no_color.is_some_and(|v| !v.is_empty()) || term == Some("dumb") {
        return Depth::None;
    }
    if colorterm
        .is_some_and(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"))
    {
        return Depth::TrueColor;
    }
    if term.is_some_and(|t| t.contains("256color")) {
        return Depth::Xterm256;
    }
    Depth::Ansi16
}

/// This process's [`Depth`], read from its environment once.
#[must_use]
pub fn depth() -> Depth {
    static DEPTH: OnceLock<Depth> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        let var = |k: &str| std::env::var(k).ok();
        depth_from(
            var("NO_COLOR").as_deref(),
            var("COLORTERM").as_deref(),
            var("TERM").as_deref(),
        )
    })
}

fn ansi(a: Ansi16) -> Color {
    match a {
        Ansi16::DefaultFg | Ansi16::DefaultBg => Color::Reset,
        Ansi16::Black => Color::Black,
        Ansi16::Red => Color::Red,
        Ansi16::Green => Color::Green,
        Ansi16::Yellow => Color::Yellow,
        Ansi16::Blue => Color::Blue,
        Ansi16::Magenta => Color::Magenta,
        Ansi16::Cyan => Color::Cyan,
        Ansi16::White => Color::Gray,
        Ansi16::BrightBlack => Color::DarkGray,
        Ansi16::BrightRed => Color::LightRed,
        Ansi16::BrightGreen => Color::LightGreen,
        Ansi16::BrightYellow => Color::LightYellow,
        Ansi16::BrightBlue => Color::LightBlue,
        Ansi16::BrightMagenta => Color::LightMagenta,
        Ansi16::BrightCyan => Color::LightCyan,
        Ansi16::BrightWhite => Color::White,
    }
}

/// The colour this terminal draws `t` as, or none at all.
#[must_use]
pub fn color(t: Token) -> Option<Color> {
    match depth() {
        Depth::None => None,
        Depth::Ansi16 => Some(ansi(t.ansi16)),
        Depth::Xterm256 => Some(Color::Indexed(t.xterm256)),
        Depth::TrueColor => Some(Color::Rgb(t.rgb.0, t.rgb.1, t.rgb.2)),
    }
}

/// A style whose foreground is `t`.
#[must_use]
pub fn fg(t: Token) -> Style {
    color(t).map_or_else(Style::default, |c| Style::default().fg(c))
}

/// The style the whole screen is drawn on: `bg.base` behind `text.primary`.
#[must_use]
pub fn base() -> Style {
    let mut s = Style::default();
    if let Some(c) = color(BG_BASE) {
        s = s.bg(c);
    }
    if let Some(c) = color(TEXT_PRIMARY) {
        s = s.fg(c);
    }
    s
}
