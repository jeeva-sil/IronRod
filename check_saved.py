#!/usr/bin/env python3
"""Diagnose recovered files — check if they are valid or damaged."""
import struct
import os
import sys

RECOVERED_DIR = "/Volumes/JeevaHDD/Recovered/Image"

def check_file(filepath):
    size = os.path.getsize(filepath)
    ext = filepath.rsplit(".", 1)[-1].lower()
    fname = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        hdr = f.read(min(512, size))

    with open(filepath, "rb") as f:
        data = f.read()

    if ext == "png":
        if hdr[:8] != b"\x89PNG\r\n\x1a\n":
            return "FAIL", f"Bad PNG header: {hdr[:8].hex()}"
        if b"IEND" in data:
            return "OK", "Valid PNG with IEND"
        return "FAIL", "PNG missing IEND (truncated)"

    elif ext in ("jpg", "jpeg"):
        if hdr[:2] != b"\xff\xd8":
            return "FAIL", f"Bad JPEG header: {hdr[:4].hex()}"
        if data[-2:] == b"\xff\xd9":
            return "OK", "Valid JPEG with FFD9 footer"
        pos = data.rfind(b"\xff\xd9")
        if pos > 0:
            trail = len(data) - pos - 2
            return "WARN", f"FFD9 at byte {pos}, {trail} trailing bytes"
        return "FAIL", "JPEG missing FFD9 (truncated)"

    elif ext == "bmp":
        if hdr[:2] != b"BM":
            return "FAIL", f"Bad BMP header: {hdr[:4].hex()}"
        declared = struct.unpack("<I", hdr[2:6])[0]
        if declared == size:
            return "OK", f"BMP size correct ({size:,} bytes)"
        elif declared > size:
            return "FAIL", f"BMP truncated: header says {declared:,}, file is {size:,}"
        else:
            return "WARN", f"BMP header says {declared:,}, file is {size:,} (extra data)"

    elif ext in ("tiff", "tif"):
        if hdr[:2] not in (b"II", b"MM"):
            return "FAIL", f"Bad TIFF header: {hdr[:4].hex()}"
        return "INFO", f"TIFF header OK, size={size:,}"

    elif ext == "ico":
        reserved = struct.unpack("<H", hdr[0:2])[0]
        img_type = struct.unpack("<H", hdr[2:4])[0]
        count = struct.unpack("<H", hdr[4:6])[0]
        if reserved != 0 or img_type not in (1, 2) or count == 0 or count > 256:
            return "FAIL", f"Bad ICO: reserved={reserved} type={img_type} count={count}"
        # Check if all image data fits
        dir_end = 6 + count * 16
        if len(data) < dir_end:
            return "FAIL", f"ICO too small for {count} entries"
        max_end = dir_end
        for i in range(count):
            off = 6 + i * 16
            if off + 16 > len(data):
                break
            img_sz = struct.unpack("<I", data[off + 8:off + 12])[0]
            img_off = struct.unpack("<I", data[off + 12:off + 16])[0]
            end = img_off + img_sz
            if end > max_end:
                max_end = end
        if max_end > size:
            return "FAIL", f"ICO data extends past EOF (need {max_end:,}, have {size:,})"
        if max_end == size:
            return "OK", f"ICO valid, {count} images"
        return "OK", f"ICO valid, {count} images (computed={max_end:,}, file={size:,})"

    return "INFO", f"Extension .{ext}, size={size:,}"


def try_pillow_open(filepath):
    """Try to actually open the file with Pillow."""
    try:
        from PIL import Image
        img = Image.open(filepath)
        img.load()  # Force full decode
        return True, f"{img.format} {img.size[0]}x{img.size[1]} {img.mode}"
    except ImportError:
        return None, "Pillow not installed"
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    d = RECOVERED_DIR
    if len(sys.argv) > 1:
        d = sys.argv[1]

    if not os.path.isdir(d):
        print(f"Directory not found: {d}")
        sys.exit(1)

    files = sorted(f for f in os.listdir(d) if not f.startswith("."))
    # Only check latest batch (Feb 12 20:19+)
    latest = []
    for f in files:
        fp = os.path.join(d, f)
        mtime = os.path.getmtime(fp)
        if mtime > 1739362700:  # Feb 12 ~20:19
            latest.append(f)

    if not latest:
        latest = files  # fallback to all

    print(f"Checking {len(latest)} files in {d}")
    print("=" * 90)
    print()

    ok = fail = warn = 0
    pillow_ok = pillow_fail = 0

    for fname in latest:
        fp = os.path.join(d, fname)
        status, detail = check_file(fp)
        size = os.path.getsize(fp)

        icon = {"OK": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️"}.get(status, "?")
        print(f"  {icon} {fname:45s} {size:>12,}  {detail}")

        if status == "OK":
            ok += 1
        elif status == "FAIL":
            fail += 1
        elif status == "WARN":
            warn += 1

        # Try Pillow
        pil_ok, pil_detail = try_pillow_open(fp)
        if pil_ok is True:
            pillow_ok += 1
            print(f"     └─ Pillow: ✅ {pil_detail}")
        elif pil_ok is False:
            pillow_fail += 1
            print(f"     └─ Pillow: ❌ {pil_detail}")

    print()
    print("=" * 90)
    print(f"  Header check:  {ok} OK, {fail} FAIL, {warn} WARN")
    if pillow_ok or pillow_fail:
        print(f"  Pillow decode:  {pillow_ok} OK, {pillow_fail} FAIL")
    print("=" * 90)
