# The Vox mark

`vox-mark.svg` is the one drawing of the Vox mark (ADR-028 L-10): a faceted V of five planes, lit
from the upper left, with one accent glint at the vertex. Its planes are text.primary at five
opacities and its glint is the accent, the token file's values (`assets/theme/vox-tokens.json`).
It has no background, so it is drawn on bg.base.

Everything else is made from it by `scripts/brand-icon.sh`, and is not edited by hand:

| File | What it is | Used by |
|---|---|---|
| `vox-icon.svg` | The mark on its plate: bg.base, the macOS icon grid (an 824 px rounded square on 1024) | The docs (`README.md`) |
| `apps/macos/Vox/Assets.xcassets/AppIcon.appiconset/` | The macOS app icon, 16 to 1024 px, with its `Contents.json`, in the app's asset catalogue | Vox.app's icon (ADR-014) |

After changing the mark, run `scripts/brand-icon.sh` (it needs `rsvg-convert`, from librsvg) and
commit what it writes. The app's build takes `AppIcon.appiconset` as it is, so it needs no SVG
renderer.
