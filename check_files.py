#!/usr/bin/env python3
"""Quick diagnostic: validate saved BMP, ICO, MPG, JPEG files."""
import struct, os, sys

RECOVERED = "/Volumes/JeevaHDD/Recovered"

def check_bmp(path, sz):
    with open(path, "rb") as fp:
        hdr = fp.read(54)
    if len(hdr) < 54:
        return "TOO_SMALL", "header < 54 bytes"
    file_sz = struct.unpack("<I", hdr[2:6])[0]
    reserved = struct.unpack("<I", hdr[6:10])[0]
    data_off = struct.unpack("<I", hdr[10:14])[0]
    dib_sz = struct.unpack("<I", hdr[14:18])[0]
    if dib_sz < 12:
        return "INVALID", f"dib_sz={dib_sz}"
    width = struct.unpack("<i", hdr[18:22])[0]
    height = struct.unpack("<i", hdr[22:26])[0]
    planes = struct.unpack("<H", hdr[26:28])[0]
    bpp = struct.unpack("<H", hdr[28:30])[0]
    issues = []
    if reserved != 0:
        issues.append(f"reserved=0x{reserved:X}")
    if dib_sz not in (12, 40, 52, 56, 108, 124):
        issues.append(f"dib_sz={dib_sz}")
    if planes != 1:
        issues.append(f"planes={planes}")
    if bpp not in (1, 4, 8, 16, 24, 32):
        issues.append(f"bpp={bpp}")
    if not (0 < abs(width) < 65536 and 0 < abs(height) < 65536):
        issues.append(f"dims={width}x{height}")
    if not (14 < data_off < 10000):
        issues.append(f"data_off={data_off}")
    info = f"{width}x{height} {bpp}bpp dib={dib_sz} hdr_sz={file_sz:,}"
    if issues:
        return "INVALID", f"{info}  [{', '.join(issues)}]"
    return "VALID", info

def check_ico(path, sz):
    with open(path, "rb") as fp:
        hdr = fp.read(6)
    if len(hdr) < 6:
        return "TOO_SMALL", ""
    reserved = struct.unpack("<H", hdr[0:2])[0]
    img_type = struct.unpack("<H", hdr[2:4])[0]
    count = struct.unpack("<H", hdr[4:6])[0]
    issues = []
    if reserved != 0:
        issues.append(f"reserved={reserved}")
    if img_type not in (1, 2):
        issues.append(f"type={img_type}")
    if count == 0 or count > 256:
        issues.append(f"count={count}")
    info = f"icons={count} type={img_type}"
    if issues:
        return "INVALID", f"{info}  [{', '.join(issues)}]"
    return "VALID", info

def check_jpg(path, sz):
    with open(path, "rb") as fp:
        hdr = fp.read(3)
        fp.seek(-2, 2)
        tail = fp.read(2)
    if hdr[:3] != b"\xFF\xD8\xFF":
        return "INVALID", f"bad header: {hdr[:3].hex()}"
    if tail != b"\xFF\xD9":
        return "TRUNCATED", f"missing FFD9 footer, tail={tail.hex()}"
    return "VALID", "header+footer OK"

def check_mpg(path, sz):
    with open(path, "rb") as fp:
        hdr = fp.read(4)
        fp.seek(-4, 2)
        tail = fp.read(4)
    valid_hdr = hdr in (b"\x00\x00\x01\xBA", b"\x00\x00\x01\xB3")
    has_end = tail == b"\x00\x00\x01\xB9"
    if not valid_hdr:
        return "INVALID", f"bad header: {hdr.hex()}"
    if not has_end:
        return "NO_END_CODE", f"tail={tail.hex()}"
    return "VALID", "header+end_code OK"

print("=" * 90)
print("  File Validation Report")
print("=" * 90)

for subdir in ("Image", "Video"):
    d = os.path.join(RECOVERED, subdir)
    if not os.path.isdir(d):
        continue
    print(f"\n{'─' * 90}")
    print(f"  {subdir}")
    print(f"{'─' * 90}")
    valid_count = 0
    invalid_count = 0
    for f in sorted(os.listdir(d)):
        path = os.path.join(d, f)
        sz = os.path.getsize(path)
        ext = f.rsplit(".", 1)[-1].lower()
        if ext == "bmp":
            status, info = check_bmp(path, sz)
        elif ext == "ico":
            status, info = check_ico(path, sz)
        elif ext in ("jpg", "jpeg"):
            status, info = check_jpg(path, sz)
        elif ext == "mpg":
            status, info = check_mpg(path, sz)
        else:
            status, info = "SKIP", ext
        
        sz_str = f"{sz:>12,}"
        tag = "✅" if status == "VALID" else "❌" if status == "INVALID" else "⚠️ "
        if status == "VALID":
            valid_count += 1
        else:
            invalid_count += 1
        print(f"  {tag} {status:10s} {f:42s} {sz_str} B  {info}")
    
    print(f"\n  Summary: {valid_count} valid, {invalid_count} invalid/other")

print(f"\n{'=' * 90}")
