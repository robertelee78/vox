# The Vox mark

`vox-mark.svg` is the one drawing of the Vox mark (ADR-028 L-10): a faceted V of five planes, lit
from the upper left, with one accent glint at the vertex. Its planes are text.primary at five
opacities and its glint is the accent, the token file's values (`assets/theme/vox-tokens.json`).
It has no background, so it is drawn on bg.base.

Everything else here is made from it by `scripts/brand-icon.sh`, and is not edited by hand:

| File | What it is | Used by |
|---|---|---|
| `vox-icon.svg` | The mark on its plate: bg.base, the macOS icon grid (an 824 px rounded square on 1024) | The docs (`README.md`) |
| `AppIcon.appiconset/` | The macOS app icon, 16 to 1024 px, with its `Contents.json` | Is to be the macOS app's icon, in its asset catalogue (ADR-014) |

After changing the mark, run `scripts/brand-icon.sh` (it needs `rsvg-convert`, from librsvg) and
commit what it writes. The app's build is to take `AppIcon.appiconset` as it is, so it needs no
SVG renderer.
