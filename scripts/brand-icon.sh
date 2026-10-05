#!/usr/bin/env bash
# Make the app icon from the Vox mark (ADR-028 L-10): one drawing, assets/brand/vox-mark.svg, and
# everything else made from it.
#
#   scripts/brand-icon.sh
#
# Writes, next to the mark:
#   vox-icon.svg               the mark on its plate (bg.base, macOS icon grid), for the docs;
#   AppIcon.appiconset/        the macOS app icon, 16 to 1024 px, with its Contents.json.
# Both are committed, so building the app needs no SVG renderer; run this again after changing
# the mark. Needs `rsvg-convert` (librsvg: `brew install librsvg`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRAND="$ROOT/assets/brand"
MARK="$BRAND/vox-mark.svg"
ICON="$BRAND/vox-icon.svg"
SET="$BRAND/AppIcon.appiconset"

if ! command -v rsvg-convert >/dev/null; then
    echo "brand-icon: rsvg-convert is not installed; run: brew install librsvg" >&2
    exit 1
fi

# The plate is Apple's macOS icon grid on a 1024 canvas: an 824 px rounded square, 100 px in from
# each edge. bg.base fills it; line.hair draws its edge. The mark's 512 square is drawn at 1.25x
# in its middle.
body="$(awk '/<\/svg>/ { inside = 0 } inside && !/<title>/ { print } /<svg[ >]/ { inside = 1 }' "$MARK")"
cat >"$ICON" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <title>Vox</title>
  <!-- Made by scripts/brand-icon.sh from vox-mark.svg: edit the mark, not this file. -->
  <rect x="100" y="100" width="824" height="824" rx="185" fill="#0c0d0f"
        stroke="#26272b" stroke-width="2"/>
  <g transform="translate(192,192) scale(1.25)">
$body
  </g>
</svg>
EOF

mkdir -p "$SET"
images=""
for spec in 16:1 16:2 32:1 32:2 128:1 128:2 256:1 256:2 512:1 512:2; do
    pt="${spec%%:*}"
    scale="${spec##*:}"
    px=$((pt * scale))
    if [ "$scale" = 1 ]; then
        name="icon_${pt}x${pt}.png"
    else
        name="icon_${pt}x${pt}@2x.png"
    fi
    rsvg-convert -w "$px" -h "$px" "$ICON" -o "$SET/$name"
    images="$images${images:+,}
    { \"idiom\" : \"mac\", \"size\" : \"${pt}x${pt}\", \"scale\" : \"${scale}x\", \"filename\" : \"$name\" }"
done
cat >"$SET/Contents.json" <<EOF
{
  "images" : [$images
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF
echo "brand-icon: wrote $ICON and $SET from $MARK"
