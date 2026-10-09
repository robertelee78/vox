# The Vox mark

`vox-mark.svg` is the drawing of the Vox mark (ADR-028 L-10): a faceted V of five planes, lit
from the upper left, with one accent glint at the vertex. Its planes are text.primary at five
opacities and its glint is the accent, the token file's values (`assets/theme/vox-tokens.json`).
It has no background, so it is drawn on bg.base. Two more drawings are the same mark where five
planes cannot hold:

- `vox-mark-small.svg`: the V as two planes, light and shadow, with heavier arms and no glint, for
  the app icon at 16 and 32 px.
- `vox-menubar.svg`: the menu bar item's template image, 18 pt: one solid V with the glint cut out
  at the vertex, black with alpha only, so macOS draws it in the menu bar's own colour.

Everything else is made from these by `scripts/brand-icon.sh`, and is not edited by hand:

| File | What it is | Used by |
|---|---|---|
| `vox-icon.svg` | The mark on its plate: bg.base, the macOS icon grid (an 824 px rounded square on 1024) | The docs (`README.md`) |
| `apps/macos/Vox/Assets.xcassets/AppIcon.appiconset/` | The macOS app icon, 16 to 1024 px, with its `Contents.json`, in the app's asset catalogue: `vox-mark.svg` on the plate, `vox-mark-small.svg` at 16 and 32 px | Vox.app's icon (ADR-014) |
| `apps/macos/Vox/Assets.xcassets/MenuBarIcon.imageset/` | `vox-menubar.svg` as a vector PDF, marked as a template image | The menu bar item (ADR-014 M-22) |

After changing a drawing, run `scripts/brand-icon.sh` (it needs `rsvg-convert`, from librsvg) and
commit what it writes. The app's build takes `AppIcon.appiconset` as it is, so it needs no SVG
renderer.
