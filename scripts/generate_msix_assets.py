#!/usr/bin/env python3
"""
Generate MSIX-required icon assets from the base app icon.

MSIX packages require specific image sizes for Start Menu tiles, taskbar,
and the App Installer UI. This script generates all required sizes.

Required assets (from AppxManifest.xml):
  Assets/Square44x44Logo.png      — Taskbar / app list icon
  Assets/Square71x71Logo.png      — Small tile (Start Menu)
  Assets/Square150x150Logo.png    — Medium tile (Start Menu)  ← required
  Assets/Square310x310Logo.png    — Large tile (Start Menu)
  Assets/Wide310x150Logo.png      — Wide tile (Start Menu)
  Assets/StoreLogo.png            — Microsoft Store / App Installer badge (50×50)
  Assets/SplashScreen.png         — Splash screen (620×300)

Scale variants (recommended for HiDPI screens):
  Each asset above can have scale-100/125/150/200/400 suffixes:
    e.g. Square44x44Logo.scale-100.png (44×44)
         Square44x44Logo.scale-200.png (88×88)
  This script generates the base size + scale-100/200 variants.

Usage:
    python scripts/generate_msix_assets.py
    python scripts/generate_msix_assets.py path/to/source.png
"""

import os
import sys

# ── Paths ──────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
ASSETS_DIR  = os.path.join(PROJECT_DIR, "msix", "Assets")
SOURCE_PNG  = os.path.join(PROJECT_DIR, "assets", "icon.png")

# ── Asset specifications ────────────────────────────────────────
# (filename_stem, width, height, background_color_or_None)
ASSETS = [
    # Name                   W     H    Background
    ("Square44x44Logo",      44,   44,  None),
    ("Square71x71Logo",      71,   71,  None),
    ("Square150x150Logo",   150,  150,  None),
    ("Square310x310Logo",   310,  310,  None),
    ("Wide310x150Logo",     310,  150,  None),
    ("StoreLogo",            50,   50,  None),
    ("SplashScreen",        620,  300,  (30, 30, 46, 255)),  # Dark background matches app
]

# Scale variants to generate for each asset (scale_factor, scale_label)
SCALES = [
    (1.0,  "scale-100"),
    (2.0,  "scale-200"),
    (1.25, "scale-125"),
    (1.5,  "scale-150"),
]


def generate_assets(source_path: str) -> None:
    """Generate all MSIX assets from a source PNG."""
    try:
        from PIL import Image
    except ImportError:
        print("❌  Pillow is required. Install with: pip install Pillow")
        sys.exit(1)

    if not os.path.exists(source_path):
        print(f"❌  Source image not found: {source_path}")
        print("    Run: python assets/generate_icons.py   to create icon.png first.")
        sys.exit(1)

    os.makedirs(ASSETS_DIR, exist_ok=True)
    print(f"📁  Output directory: {ASSETS_DIR}")
    print(f"🖼   Source image:     {source_path}")
    print()

    src = Image.open(source_path).convert("RGBA")

    for stem, base_w, base_h, bg_color in ASSETS:
        for scale_factor, scale_label in SCALES:
            w = int(base_w * scale_factor)
            h = int(base_h * scale_factor)

            # Create canvas
            if bg_color:
                canvas = Image.new("RGBA", (w, h), bg_color)
            else:
                canvas = Image.new("RGBA", (w, h), (0, 0, 0, 0))

            if stem == "SplashScreen":
                # Splash: center the icon at ~40% height, scale to fit nicely
                icon_size = int(min(w, h) * 0.55)
                icon = src.copy()
                icon.thumbnail((icon_size, icon_size), Image.LANCZOS)
                offset_x = (w - icon.width) // 2
                offset_y = (h - icon.height) // 2
                canvas.paste(icon, (offset_x, offset_y), icon)
            elif stem == "Wide310x150Logo":
                # Wide tile: icon on left, padded
                icon_size = int(h * 0.80)
                icon = src.copy()
                icon.thumbnail((icon_size, icon_size), Image.LANCZOS)
                padding = int(h * 0.10)
                canvas.paste(icon, (padding, (h - icon.height) // 2), icon)
            else:
                # Square tiles: icon centered with padding
                padding_pct = 0.10
                icon_size = int(min(w, h) * (1.0 - 2 * padding_pct))
                icon = src.copy()
                icon.thumbnail((icon_size, icon_size), Image.LANCZOS)
                offset_x = (w - icon.width) // 2
                offset_y = (h - icon.height) // 2
                canvas.paste(icon, (offset_x, offset_y), icon)

            # Save base (scale-100) as both bare name and scaled name
            out_path = os.path.join(ASSETS_DIR, f"{stem}.{scale_label}.png")
            canvas.save(out_path, "PNG", optimize=True)

            # Also save as bare filename for the scale-100 variant
            if scale_label == "scale-100":
                bare_path = os.path.join(ASSETS_DIR, f"{stem}.png")
                canvas.save(bare_path, "PNG", optimize=True)
                print(f"   ✅  {stem}.png ({w}×{h})  +  {scale_label}")
            else:
                print(f"       {stem}.{scale_label}.png ({w}×{h})")

    print()
    print(f"✅  Generated {len(ASSETS)} assets ({len(ASSETS) * len(SCALES)} files total)")
    print(f"    in: {ASSETS_DIR}")


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE_PNG

    # If source doesn't exist, try to generate it
    if not os.path.exists(source):
        gen_script = os.path.join(PROJECT_DIR, "assets", "generate_icons.py")
        if os.path.exists(gen_script):
            print(f"🎨  icon.png not found. Generating from assets/generate_icons.py ...")
            import subprocess
            result = subprocess.run(
                [sys.executable, gen_script],
                cwd=PROJECT_DIR
            )
            if result.returncode != 0 or not os.path.exists(source):
                print("❌  Failed to generate source icon.")
                sys.exit(1)
        else:
            print(f"❌  Source image not found: {source}")
            sys.exit(1)

    generate_assets(source)


if __name__ == "__main__":
    main()
