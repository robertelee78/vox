#!/usr/bin/env bash
# Make the app icon and the menu bar image from the Vox mark (ADR-028 L-10): three drawings in
# assets/brand (the mark, its small form, its menu bar form), and everything else made from them.
#
#   scripts/brand-icon.sh
#
# Writes:
#   assets/brand/vox-icon.svg  the mark on its plate (bg.base, macOS icon grid), for the docs;
#   apps/macos/Vox/Assets.xcassets/AppIcon.appiconset/
#                              the macOS app icon, 16 to 1024 px, with its Contents.json, in the
#                              app's own asset catalogue (Xcode's asset compiler does not follow a
#                              symbolic link, so it lives there and nowhere else): vox-mark.svg on
#                              its plate, and at 16 and 32 px vox-mark-small.svg, which holds there;
#   apps/macos/Vox/Assets.xcassets/MenuBarIcon.imageset/
#                              the menu bar item's template image, vox-menubar.svg as a vector PDF.
# Both are committed, so building the app needs no SVG renderer; run this again after changing
# the mark. Needs `rsvg-convert` (librsvg: `brew install librsvg`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRAND="$ROOT/assets/brand"
MARK="$BRAND/vox-mark.svg"
SMALL="$BRAND/vox-mark-small.svg"
MENUBAR="$BRAND/vox-menubar.svg"
ICON="$BRAND/vox-icon.svg"
ASSETS="$ROOT/apps/macos/Vox/Assets.xcassets"
SET="$ASSETS/AppIcon.appiconset"
BAR="$ASSETS/MenuBarIcon.imageset"

if ! command -v rsvg-convert >/dev/null; then
    echo "brand-icon: rsvg-convert is not installed; run: brew install librsvg" >&2
    exit 1
fi

# The plate is Apple's macOS icon grid on a 1024 canvas: an 824 px rounded square, 100 px in from
# each edge. bg.base fills it, and a 4 px edge a little lighter than line.hair (#3a3b40) keeps it
# apart from a dark Dock. A mark's 512 square is drawn in its middle at `scale`, `ty` from the top:
# a V's weight is at its top, so it sits a little low to look centred.
# plate MARK SCALE TY OUT
plate() {
    local body tx
    body="$(awk '/<\/svg>/ { inside = 0 } inside && !/<title>/ { print } /<svg[ >]/ { inside = 1 }' "$1")"
    tx="$(awk -v s="$2" 'BEGIN { printf "%g", 512 - 256 * s }')"
    cat >"$4" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <title>Vox</title>
  <!-- Made by scripts/brand-icon.sh from $(basename "$1"): edit the mark, not this file. -->
  <rect x="100" y="100" width="824" height="824" rx="185" fill="#0c0d0f"
        stroke="#3a3b40" stroke-width="4"/>
  <g transform="translate($tx,$3) scale($2)">
$body
  </g>
</svg>
EOF
}
plate "$MARK" 1.36 186 "$ICON"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SMALL_ICON="$WORK/vox-icon-small.svg"
plate "$SMALL" 1.5 128 "$SMALL_ICON"

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
    # At 16 and 32 px the five planes and the glint blur into one shape: the small mark holds.
    if [ "$px" -le 32 ]; then from="$SMALL_ICON"; else from="$ICON"; fi
    rsvg-convert -w "$px" -h "$px" "$from" -o "$SET/$name"
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

# The menu bar image: a template (black with alpha; macOS colours it for the bar), kept as a vector
# PDF so it is sharp at every scale. At 72 dpi its 18 px are 18 pt; at rsvg-convert's own 90 they
# were 13.5.
mkdir -p "$BAR"
rsvg-convert -f pdf -d 72 -p 72 "$MENUBAR" -o "$BAR/MenuBarIcon.pdf"
cat >"$BAR/Contents.json" <<EOF
{
  "images" : [
    { "idiom" : "universal", "filename" : "MenuBarIcon.pdf" }
  ],
  "info" : { "author" : "xcode", "version" : 1 },
  "properties" : {
    "preserves-vector-representation" : true,
    "template-rendering-intent" : "template"
  }
}
EOF
echo "brand-icon: wrote $ICON, $SET and $BAR from $MARK, $SMALL and $MENUBAR"
