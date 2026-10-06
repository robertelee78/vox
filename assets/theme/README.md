# The token file

`vox-tokens.json` is the only place a colour, a typeface or a motion value is defined (ADR-028
L-1, L-2). Schema `vox-tokens/1`:

- `theme`: `"dark"`, the only theme.
- `color`: exactly the colours ADR-028 L-2 names, each `{ "hex": "#rrggbb", "xterm256": 16–255,
  "ansi16": <slot> }`, where a slot is `default-fg`, `default-bg`, `black`, `red`, `green`,
  `yellow`, `blue`, `magenta`, `cyan`, `white`, or one of those prefixed `bright-`.
- `type`: the app's faces, each `{ "family", "weight": 100–900 }` with exactly one of `"system"`
  (a system font role: a text style the app follows the system's text size by, `body`, `title`,
  `caption` and the rest of SwiftUI's `Font.TextStyle` names, or `monospaced`) or `"bundled"` (a
  font file the app ships), and optionally `"tracking"` (em), `"uppercase"`, `"size"` (pt).
- `motion`: numbers, by name (frame counts, milliseconds, damping).

Who reads it:

- **The TUI** at build time: `crates/vox-tui/build.rs` turns it into constants
  (`theme::BG_BASE`, `theme::ACCENT`, …) drawn by `crates/vox-tui/src/theme.rs` in truecolour,
  the xterm 256-colour index or the 16-colour slot, as the terminal declares, and in no colour under
  `NO_COLOR`.
- **The macOS app** at build time: `cargo run -p vox-theme -- swift assets/theme/vox-tokens.json
  <out-dir>` writes `<out-dir>/VoxTokens.xcassets` (one colour set per colour, named in UpperCamel:
  `BgBase`, `Accent`, …) and `<out-dir>/VoxTokens.swift` (`VoxTokens.Colors.bgBase`,
  `VoxTokens.Fonts.appMono`, `VoxTokens.Motion.appSpringResponseMs`, …).

`crates/vox-theme` checks the file and refuses one it cannot read, with the reason; a build of
either client stops on it.
