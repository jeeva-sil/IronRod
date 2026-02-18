#!/usr/bin/env python3
"""Check what data format is actually in each TSK-saved file."""
import os, struct

d = "/Volumes/JeevaHDD/Recovered/Image"
tsk_files = [
    "recovered_000001.png", "recovered_000002.png", "recovered_000003.png",
    "recovered_000004.jpg", "recovered_000005.png", "recovered_000006.tiff",
    "recovered_000007.bmp", "recovered_000008.png", "recovered_000009.png",
    "recovered_000010.ico", "recovered_000011.ico", "recovered_000012.ico",
    "recovered_000013.ico",
]

for f in tsk_files:
    fp = os.path.join(d, f)
    if not os.path.exists(fp):
        continue
    with open(fp, "rb") as fh:
        hdr = fh.read(32)
    sz = os.path.getsize(fp)
    print(f"{f} ({sz:,} bytes):")
    print(f"  hex: {hdr[:16].hex()}")
    if hdr[:2] == b"\xff\xd8":
        print("  -> Actually JPEG data")
    elif hdr[:8] == b"\x89PNG\r\n\x1a\n":
        print("  -> Actually PNG data (correct)")
    elif hdr[:2] == b"BM":
        print("  -> Actually BMP data")
    elif hdr[:2] in (b"II", b"MM"):
        print("  -> Actually TIFF data")
    elif hdr[:4] == b"RIFF":
        print("  -> Actually RIFF data")
    elif all(b == 0 for b in hdr[:16]):
        print("  -> All zeros (overwritten/TRIMmed)")
    else:
        print("  -> Unknown/garbage data")
    print()

# Now check a few carved BMPs with Pillow
print("--- Checking carved BMPs with deeper analysis ---")
carved_bmps = [f for f in os.listdir(d) if f.endswith(".bmp") and not f.startswith(".")]
carved_bmps.sort()
for f in carved_bmps[:5]:
    fp = os.path.join(d, f)
    with open(fp, "rb") as fh:
        hdr = fh.read(54)
    sz = os.path.getsize(fp)
    if hdr[:2] == b"BM":
        file_size = struct.unpack("<I", hdr[2:6])[0]
        data_off = struct.unpack("<I", hdr[10:14])[0]
        dib_sz = struct.unpack("<I", hdr[14:18])[0]
        width = struct.unpack("<i", hdr[18:22])[0]
        height = struct.unpack("<i", hdr[22:26])[0]
        planes = struct.unpack("<H", hdr[26:28])[0]
        bpp = struct.unpack("<H", hdr[28:30])[0]
        compress = struct.unpack("<I", hdr[30:34])[0]
        print(f"{f}: {width}x{abs(height)} {bpp}bpp compress={compress} dib={dib_sz} dataoff={data_off} file_size={file_size} actual={sz}")
