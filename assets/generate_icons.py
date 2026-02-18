#!/usr/bin/env python3
"""
Generate app icons for all platforms from a base PNG image.

Usage:
    python assets/generate_icons.py                  # Uses default generated icon
    python assets/generate_icons.py my_logo.png      # Uses custom source image

Generates:
    assets/icon.png    — 1024x1024 PNG (Linux / source)
    assets/icon.ico    — Windows multi-size ICO
    assets/icon.icns   — macOS ICNS bundle
"""

import os
import sys
import struct

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))


def create_default_icon():
    """Create a simple but professional icon using Pillow."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("Pillow not installed. Install with: pip install Pillow")
        print("Generating a minimal placeholder icon instead...")
        return create_minimal_placeholder()

    size = 1024
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background — rounded rectangle (dark blue-purple gradient feel)
    # Draw circle background
    padding = 40
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=(30, 30, 46, 255),       # Dark background
        outline=(122, 162, 247, 255),  # Blue accent border
        width=12,
    )

    # Inner shield / drive shape
    cx, cy = size // 2, size // 2
    # Hard drive icon representation
    drive_w, drive_h = 400, 280
    drive_x = cx - drive_w // 2
    drive_y = cy - drive_h // 2 + 30

    # Drive body
    draw.rounded_rectangle(
        [drive_x, drive_y, drive_x + drive_w, drive_y + drive_h],
        radius=30,
        fill=(42, 42, 60, 255),
        outline=(122, 162, 247, 255),
        width=6,
    )

    # Drive platter (circle)
    platter_r = 90
    draw.ellipse(
        [cx - platter_r - 40, cy - platter_r + 20,
         cx + platter_r - 40, cy + platter_r + 20],
        outline=(158, 206, 106, 255),  # Green
        width=5,
    )
    # Center dot
    draw.ellipse(
        [cx - 15 - 40, cy - 15 + 20, cx + 15 - 40, cy + 15 + 20],
        fill=(158, 206, 106, 255),
    )

    # Recovery arrow (circular arrow at bottom-right of platter)
    arrow_cx = cx + 100
    arrow_cy = cy + 30
    arrow_r = 50
    draw.arc(
        [arrow_cx - arrow_r, arrow_cy - arrow_r,
         arrow_cx + arrow_r, arrow_cy + arrow_r],
        start=200, end=340,
        fill=(122, 162, 247, 255),
        width=8,
    )
    # Arrowhead
    draw.polygon(
        [(arrow_cx + 20, arrow_cy - arrow_r + 5),
         (arrow_cx + 45, arrow_cy - arrow_r + 20),
         (arrow_cx + 20, arrow_cy - arrow_r + 35)],
        fill=(122, 162, 247, 255),
    )

    # Text label "IR" at the top
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 120)
    except (IOError, OSError):
        try:
            font = ImageFont.truetype("arial.ttf", 120)
        except (IOError, OSError):
            font = ImageFont.load_default()

    draw.text(
        (cx, cy - 220),
        "IR",
        fill=(224, 224, 232, 255),
        font=font,
        anchor="mm",
    )

    return img


def create_minimal_placeholder():
    """Create a minimal 64x64 icon without Pillow (BMP format)."""
    # Generate a simple 64x64 blue square BMP as placeholder
    w = h = 64
    row_size = (w * 3 + 3) & ~3
    pixel_data = bytearray()
    for y in range(h):
        for x in range(w):
            # Simple blue gradient
            pixel_data.extend([200, int(162 * y / h), int(30 + 90 * x / w)])
        pixel_data.extend(b'\x00' * (row_size - w * 3))

    # BMP header
    file_size = 54 + len(pixel_data)
    bmp = bytearray()
    bmp += b'BM'
    bmp += struct.pack('<I', file_size)
    bmp += b'\x00\x00\x00\x00'
    bmp += struct.pack('<I', 54)
    bmp += struct.pack('<I', 40)
    bmp += struct.pack('<i', w)
    bmp += struct.pack('<i', h)
    bmp += struct.pack('<HH', 1, 24)
    bmp += struct.pack('<I', 0)
    bmp += struct.pack('<I', len(pixel_data))
    bmp += struct.pack('<i', 2835)
    bmp += struct.pack('<i', 2835)
    bmp += struct.pack('<I', 0)
    bmp += struct.pack('<I', 0)
    bmp += pixel_data

    path = os.path.join(ASSETS_DIR, 'icon.bmp')
    with open(path, 'wb') as f:
        f.write(bmp)
    print(f"  Created placeholder: {path}")
    print("  ⚠  Install Pillow for proper icon generation: pip install Pillow")
    return None


def save_icons(img):
    """Save icon in all platform formats."""
    if img is None:
        return

    # PNG — 1024x1024 (Linux, source)
    png_path = os.path.join(ASSETS_DIR, 'icon.png')
    img.save(png_path, 'PNG')
    print(f"  ✅ {png_path} (1024x1024)")

    # ICO — Windows (multiple sizes)
    ico_path = os.path.join(ASSETS_DIR, 'icon.ico')
    ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_images = [img.resize(s, resample=3) for s in ico_sizes]  # LANCZOS = 3
    ico_images[0].save(ico_path, format='ICO', sizes=ico_sizes)
    print(f"  ✅ {ico_path} (16–256px)")

    # ICNS — macOS
    icns_path = os.path.join(ASSETS_DIR, 'icon.icns')
    try:
        # macOS: use iconutil if available
        import subprocess
        import tempfile
        iconset_dir = os.path.join(tempfile.mkdtemp(), 'icon.iconset')
        os.makedirs(iconset_dir)
        icns_sizes = {
            'icon_16x16.png': 16,
            'icon_16x16@2x.png': 32,
            'icon_32x32.png': 32,
            'icon_32x32@2x.png': 64,
            'icon_128x128.png': 128,
            'icon_128x128@2x.png': 256,
            'icon_256x256.png': 256,
            'icon_256x256@2x.png': 512,
            'icon_512x512.png': 512,
            'icon_512x512@2x.png': 1024,
        }
        for name, s in icns_sizes.items():
            resized = img.resize((s, s), resample=3)
            resized.save(os.path.join(iconset_dir, name), 'PNG')
        subprocess.run(
            ['iconutil', '-c', 'icns', iconset_dir, '-o', icns_path],
            check=True, capture_output=True,
        )
        print(f"  ✅ {icns_path} (macOS iconutil)")
    except (FileNotFoundError, subprocess.CalledProcessError):
        # Fallback: save as PNG (PyInstaller can use PNG on macOS too)
        img.resize((512, 512), resample=3).save(icns_path.replace('.icns', '.png'), 'PNG')
        print(f"  ⚠  iconutil not found — saved icon.png instead (use on macOS to generate .icns)")


def main():
    print("🎨 Generating IronRod app icons...")
    print()

    if len(sys.argv) > 1:
        # Custom source image
        source_path = sys.argv[1]
        try:
            from PIL import Image
            img = Image.open(source_path).convert('RGBA')
            img = img.resize((1024, 1024), resample=3)
            print(f"  Using custom image: {source_path}")
        except ImportError:
            print("Pillow required for custom images: pip install Pillow")
            sys.exit(1)
    else:
        img = create_default_icon()

    save_icons(img)
    print()
    print("Done! Icons saved to assets/")


if __name__ == '__main__':
    main()
