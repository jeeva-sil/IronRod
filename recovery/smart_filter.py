"""
Smart Filter — Validation & deduplication for ALL recovered image/video files.

Supported image formats:
  JPEG, PNG, GIF, BMP, TIFF, WebP, JPEG 2000, PSD, ICO, TGA,
  HEIC, AVIF, CR2, NEF, ARW, DNG, ORF, RW2, RAF

Supported video formats:
  MP4, MOV, 3GP, M4V, AVI, MKV, WebM, FLV, WMV, MPG, TS, VOB,
  OGV, RM, SWF

Key design decisions:
  • MAX_ENTROPY raised to 7.9999 — compressed media regularly hit 7.98+
  • MIN_ENTROPY lowered to 1.0 — some valid PNGs with large flat areas
  • Each format only checks the critical header bytes — we do NOT over-validate
  • Unknown extensions get a generic header + entropy check
"""

from __future__ import annotations

import io
import math
import hashlib
import struct
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Pillow for deep image validation ─────────────────────────
try:
    from PIL import Image as _PILImage
    # Suppress DecompressionBombWarning for large recovered images.
    # These are legitimate files, not attacks — data recovery regularly
    # produces large uncompressed BMPs (100+ MP).
    _PILImage.MAX_IMAGE_PIXELS = None
    _HAS_PILLOW = True
except ImportError:
    _HAS_PILLOW = False
    logger.info("Pillow not installed — deep image validation disabled")

# ── Thresholds ────────────────────────────────────────────────
MIN_FILE_SIZE = 4 * 1024        # 4 KB minimum
MIN_FILE_SIZE_SMALL = 256       # for ICO and other small formats
MIN_ENTROPY = 1.0               # was 2.0, too aggressive
MAX_ENTROPY = 7.9999            # was 7.99, rejected valid JPEGs


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0–8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


# ══════════════════════════════════════════════════════════════
#  Per-type validators — IMAGE
# ══════════════════════════════════════════════════════════════

def validate_jpeg(data: bytes) -> bool:
    """Accept any data starting with FF D8 FF xx where xx is a valid marker."""
    if len(data) < 4 or data[:2] != b"\xFF\xD8":
        return False
    if data[2] != 0xFF:
        return False
    m = data[3]
    if m < 0xC0:
        return False
    if 0xD0 <= m <= 0xD7:
        return False
    return True


def validate_png(data: bytes) -> bool:
    """Check PNG magic and that first chunk is IHDR."""
    if len(data) < 24:
        return False
    if data[:8] != b"\x89PNG\r\n\x1A\n":
        return False
    return data[12:16] == b"IHDR"


def validate_gif(data: bytes) -> bool:
    """Check GIF87a or GIF89a magic."""
    if len(data) < 13:
        return False
    return data[:6] in (b"GIF87a", b"GIF89a")


def validate_bmp(data: bytes) -> bool:
    """Strict BMP validation — rejects false-positive 'BM' matches.

    Checks: magic, reserved bytes, DIB header size, planes, bpp,
    image dimensions, data offset, and embedded file size.
    """
    if len(data) < 54:
        return False
    if data[:2] != b"BM":
        return False

    file_size = struct.unpack("<I", data[2:6])[0]
    reserved1 = struct.unpack("<H", data[6:8])[0]
    reserved2 = struct.unpack("<H", data[8:10])[0]
    data_off = struct.unpack("<I", data[10:14])[0]

    # Reserved fields MUST be zero in a valid BMP
    if reserved1 != 0 or reserved2 != 0:
        return False

    # DIB header size must be one of the standard values
    dib_sz = struct.unpack("<I", data[14:18])[0]
    _VALID_DIB_SIZES = {12, 40, 52, 56, 64, 108, 124}
    if dib_sz not in _VALID_DIB_SIZES:
        return False

    # For BITMAPINFOHEADER (40+) check planes, bpp, dimensions
    if dib_sz >= 40 and len(data) >= 30:
        width = struct.unpack("<i", data[18:22])[0]   # signed
        height = struct.unpack("<i", data[22:26])[0]   # signed (neg = top-down)
        planes = struct.unpack("<H", data[26:28])[0]
        bpp = struct.unpack("<H", data[28:30])[0]

        if planes != 1:
            return False
        if bpp not in (1, 2, 4, 8, 16, 24, 32):
            return False
        if abs(width) == 0 or abs(width) > 65536:
            return False
        if abs(height) == 0 or abs(height) > 65536:
            return False

    # Data offset must be sane (at least 14 + dib_sz, at most file_size)
    if data_off < 14 + dib_sz:
        return False

    # File size must be >= 54 and <= 500 MB
    if file_size < 54 or file_size > 500 * 1024 * 1024:
        return False

    # Data offset should not exceed file size
    if data_off > file_size:
        return False

    return True


def validate_tiff(data: bytes) -> bool:
    """Check TIFF magic (II or MM) and version number 42."""
    if len(data) < 8:
        return False
    if data[:2] == b"II":
        version = struct.unpack("<H", data[2:4])[0]
    elif data[:2] == b"MM":
        version = struct.unpack(">H", data[2:4])[0]
    else:
        return False
    return version == 42


def validate_webp(data: bytes) -> bool:
    """Check RIFF + WEBP markers."""
    if len(data) < 12:
        return False
    return data[:4] == b"RIFF" and data[8:12] == b"WEBP"


def validate_jp2(data: bytes) -> bool:
    """Check JPEG 2000 signature box."""
    if len(data) < 12:
        return False
    return data[:12] == b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A"


def validate_psd(data: bytes) -> bool:
    """Check Photoshop 8BPS magic and version."""
    if len(data) < 6:
        return False
    if data[:4] != b"8BPS":
        return False
    version = struct.unpack(">H", data[4:6])[0]
    return version in (1, 2)  # 1 = PSD, 2 = PSB


def validate_ico(data: bytes) -> bool:
    """Strict ICO validation: reserved=0, type=1 (icon) or 2 (cursor),
    image count > 0, and directory entries must have sane offsets/sizes."""
    if len(data) < 6:
        return False
    reserved = struct.unpack("<H", data[0:2])[0]
    img_type = struct.unpack("<H", data[2:4])[0]
    count = struct.unpack("<H", data[4:6])[0]

    if reserved != 0:
        return False
    if img_type not in (1, 2):  # 1=icon, 2=cursor
        return False
    if count == 0 or count > 256:
        return False

    # Validate at least the first directory entry if we have enough data
    dir_end = 6 + count * 16
    if len(data) >= min(dir_end, 22):
        # Check first entry: img_size and img_offset must be reasonable
        entry_off = 6
        if entry_off + 16 <= len(data):
            img_sz = struct.unpack("<I", data[entry_off + 8:entry_off + 12])[0]
            img_off = struct.unpack("<I", data[entry_off + 12:entry_off + 16])[0]
            # Offset must be >= directory end
            if img_off < dir_end:
                return False
            # Image data size must be > 0 and < 10MB (single icon)
            if img_sz == 0 or img_sz > 10 * 1024 * 1024:
                return False

    return True


def validate_raf(data: bytes) -> bool:
    """Check Fujifilm RAW magic."""
    if len(data) < 16:
        return False
    return data[:16] == b"FUJIFILMCCD-RAW "


# ══════════════════════════════════════════════════════════════
#  Per-type validators — VIDEO
# ══════════════════════════════════════════════════════════════

def validate_isobmff(data: bytes) -> bool:
    """Validate an ISO Base Media file (MP4, MOV, HEIC, 3GP, M4V, AVIF)."""
    if len(data) < 12:
        return False
    try:
        box_size = struct.unpack(">I", data[:4])[0]
        box_type = data[4:8]
        if box_type != b"ftyp":
            return False
        if box_size < 8 or box_size > 4096:
            return False
        return True
    except (struct.error, IndexError):
        return False


def validate_avi(data: bytes) -> bool:
    """Check RIFF + AVI markers."""
    if len(data) < 12:
        return False
    return data[:4] == b"RIFF" and data[8:12] == b"AVI "


def validate_mkv(data: bytes) -> bool:
    """Check EBML magic header (used by MKV and WebM)."""
    if len(data) < 4:
        return False
    return data[:4] == b"\x1A\x45\xDF\xA3"


def validate_flv(data: bytes) -> bool:
    """Check FLV header."""
    if len(data) < 9:
        return False
    if data[:3] != b"FLV":
        return False
    version = data[3]
    if version < 1 or version > 10:
        return False
    return True


def validate_wmv(data: bytes) -> bool:
    """Check ASF/WMV header GUID."""
    if len(data) < 16:
        return False
    return data[:8] == b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"


def validate_mpg(data: bytes) -> bool:
    """MPEG-PS / MPEG-1 / MPEG-2 validation.

    Accepts any data that starts with a valid MPEG start code
    (00 00 01 xx) where xx is a known MPEG stream ID.
    Also handles files with a small amount of zero-padding before
    the first start code.
    """
    if len(data) < 12:
        return False

    # Try to find an MPEG start code at the beginning
    # Some files have a few bytes of padding before the first start code
    start = _find_mpeg_start_code(data, max_offset=32)
    if start < 0:
        return False

    code = data[start + 3]  # The stream ID byte after 00 00 01

    # ── MPEG-1 sequence header: 00 00 01 B3 ──
    if code == 0xB3 and start + 12 <= len(data):
        h_size = (data[start + 4] << 4) | (data[start + 5] >> 4)
        v_size = ((data[start + 5] & 0x0F) << 8) | data[start + 6]
        if h_size == 0 or h_size > 7680:
            return False
        if v_size == 0 or v_size > 4320:
            return False
        aspect_ratio = (data[start + 7] >> 4) & 0x0F
        frame_rate = data[start + 7] & 0x0F
        if aspect_ratio == 0:
            return False
        if frame_rate == 0 or frame_rate > 8:
            return False
        return True

    # ── MPEG-PS pack header: 00 00 01 BA ──
    if code == 0xBA:
        b4 = data[start + 4]
        if (b4 & 0xC0) == 0x40:   # MPEG-2 pack
            return True
        if (b4 & 0xF0) == 0x20:   # MPEG-1 pack
            return True
        return False

    # ── Other valid MPEG start codes ──
    # B7=seq end, B8=GOP, B9=PS end, BB=system header,
    # BC=program stream map, BD/BF=private, BE=padding,
    # C0-DF=audio streams, E0-EF=video streams
    if code in (0xB7, 0xB8, 0xB9, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
        return True
    if 0xC0 <= code <= 0xDF:  # audio stream
        return True
    if 0xE0 <= code <= 0xEF:  # video stream
        return True

    return False


def _find_mpeg_start_code(data: bytes, max_offset: int = 32) -> int:
    """Find the first MPEG start code (00 00 01) within max_offset bytes."""
    limit = min(max_offset, len(data) - 4)
    for i in range(limit + 1):
        if data[i:i + 3] == b"\x00\x00\x01":
            return i
    return -1


def validate_ts(data: bytes) -> bool:
    """Check for 3+ consecutive MPEG-TS sync bytes at 188-byte intervals."""
    if len(data) < 188 * 3:
        return False
    for i in range(3):
        if data[i * 188] != 0x47:
            return False
    return True


def validate_vob(data: bytes) -> bool:
    """VOB uses MPEG-PS format."""
    return validate_mpg(data)


def validate_ogv(data: bytes) -> bool:
    """Check OGG container magic."""
    if len(data) < 4:
        return False
    return data[:4] == b"OggS"


def validate_rm(data: bytes) -> bool:
    """Check RealMedia magic."""
    if len(data) < 4:
        return False
    return data[:4] == b".RMF"


def validate_swf(data: bytes) -> bool:
    """Check SWF magic (FWS or CWS)."""
    if len(data) < 8:
        return False
    return data[:3] in (b"FWS", b"CWS")


# ══════════════════════════════════════════════════════════════
#  Per-type validators — AUDIO
# ══════════════════════════════════════════════════════════════

def validate_mp3(data: bytes) -> bool:
    """Validate MP3 — check for ID3v2 tag or valid MPEG frame sync."""
    if len(data) < 4:
        return False
    # ID3v2 tag at the start
    if data[:3] == b"ID3":
        if len(data) < 10:
            return False
        # ID3 version should be 2.x, 3.x, or 4.x
        version = data[3]
        return version in (2, 3, 4)
    # MPEG frame sync (11 set bits = 0xFF + upper 3 bits of next byte)
    if data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        # Validate MPEG audio version (bits 4-3 of byte 1)
        version = (data[1] >> 3) & 0x03
        if version == 1:  # Reserved
            return False
        # Validate layer (bits 2-1 of byte 1)
        layer = (data[1] >> 1) & 0x03
        if layer == 0:  # Reserved
            return False
        # Validate bitrate index (byte 2, upper nibble)
        bitrate_idx = (data[2] >> 4) & 0x0F
        if bitrate_idx == 0x0F:  # Invalid
            return False
        # Validate sample rate index (byte 2, bits 3-2)
        sample_idx = (data[2] >> 2) & 0x03
        if sample_idx == 0x03:  # Reserved
            return False
        return True
    return False


def validate_wav(data: bytes) -> bool:
    """Validate WAV — RIFF + WAVE sub-type + fmt chunk."""
    if len(data) < 16:
        return False
    if data[:4] != b"RIFF":
        return False
    if data[8:12] != b"WAVE":
        return False
    # Should have 'fmt ' chunk nearby
    if data[12:16] == b"fmt ":
        return True
    # Sometimes JUNK chunk comes before fmt
    return b"fmt " in data[:256]


def validate_flac(data: bytes) -> bool:
    """Validate FLAC — check magic + STREAMINFO metadata block."""
    if len(data) < 8:
        return False
    if data[:4] != b"fLaC":
        return False
    # First metadata block type should be STREAMINFO (0x00 or 0x80)
    block_type = data[4] & 0x7F  # Mask out 'last-block' flag
    return block_type == 0  # STREAMINFO


def validate_aiff(data: bytes) -> bool:
    """Validate AIFF — FORM + AIFF/AIFC sub-type."""
    if len(data) < 12:
        return False
    if data[:4] != b"FORM":
        return False
    return data[8:12] in (b"AIFF", b"AIFC")


def validate_midi(data: bytes) -> bool:
    """Validate MIDI — MThd header + valid header length."""
    if len(data) < 14:
        return False
    if data[:4] != b"MThd":
        return False
    # Header length should be 6
    hdr_len = struct.unpack(">I", data[4:8])[0]
    return hdr_len == 6


# ══════════════════════════════════════════════════════════════
#  Per-type validators — DOCUMENT
# ══════════════════════════════════════════════════════════════

def validate_pdf(data: bytes) -> bool:
    """Validate PDF — check header and version."""
    if len(data) < 8:
        return False
    if not data[:5].startswith(b"%PDF-"):
        return False
    # Version should be 1.x or 2.x
    try:
        ver_str = data[5:8].decode("ascii", errors="replace")
        major = int(ver_str[0])
        return major in (1, 2)
    except (ValueError, IndexError):
        return False


def validate_zip(data: bytes) -> bool:
    """Validate ZIP — PK signature + valid version."""
    if len(data) < 30:
        return False
    if data[:4] != b"PK\x03\x04":
        return False
    # Version needed (2 bytes at offset 4) — should be reasonable
    version = struct.unpack("<H", data[4:6])[0]
    if version > 100:  # Unreasonably high version
        return False
    # Compressed size and filename length should be present
    fn_len = struct.unpack("<H", data[26:28])[0]
    if fn_len == 0 or fn_len > 1024:
        return False
    return True


def validate_sqlite(data: bytes) -> bool:
    """Validate SQLite — check header string and page size."""
    if len(data) < 100:
        return False
    if data[:16] != b"SQLite format 3\x00":
        return False
    # Page size at offset 16 (2 bytes, big-endian) — must be power of 2
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536  # Special case per SQLite spec
    if page_size < 512 or page_size > 65536:
        return False
    return (page_size & (page_size - 1)) == 0  # Power of 2


# ═══════════════════════════════════════════════════════════════
#  NEW VALIDATORS — Archives, Executables, Fonts, Database, etc.
# ═══════════════════════════════════════════════════════════════

def validate_rtf(data: bytes) -> bool:
    """Validate RTF — check header and braces."""
    if len(data) < 10:
        return False
    if not data[:5] == b"{\\rtf":
        return False
    # Must have at least one closing brace
    return b"}" in data[:min(len(data), 4096)]


def validate_xml(data: bytes) -> bool:
    """Validate XML — check for valid XML prolog."""
    if len(data) < 10:
        return False
    # Skip BOM if present
    start = data[:10]
    if start[:3] == b"\xEF\xBB\xBF":
        start = data[3:13]
    return start[:5] == b"<?xml" or start[:2] == b"<?"


def validate_html(data: bytes) -> bool:
    """Validate HTML — check for HTML markers."""
    if len(data) < 15:
        return False
    lower = data[:256].lower()
    return (b"<!doctype html" in lower or b"<html" in lower
            or b"<head" in lower or b"<body" in lower)


def validate_eps(data: bytes) -> bool:
    """Validate EPS — PostScript header."""
    if len(data) < 14:
        return False
    return data[:11] == b"%!PS-Adobe-"


def validate_ole2(data: bytes) -> bool:
    """Validate OLE2/CFB — Microsoft Compound Binary Format."""
    if len(data) < 512:
        return False
    if data[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return False
    # Minor version at offset 0x18, major at 0x1A
    major = struct.unpack("<H", data[0x1A:0x1C])[0]
    return major in (3, 4)  # CFB v3 or v4


def validate_7z(data: bytes) -> bool:
    """Validate 7-Zip archive."""
    if len(data) < 32:
        return False
    if data[:6] != b"7z\xBC\xAF\x27\x1C":
        return False
    # Major/minor version at offset 6-7
    major = data[6]
    return major == 0  # Current 7z version


def validate_rar(data: bytes) -> bool:
    """Validate RAR archive (v4 or v5)."""
    if len(data) < 12:
        return False
    if data[:7] == b"Rar!\x1A\x07\x00":
        return True  # RAR 4
    if data[:8] == b"Rar!\x1A\x07\x01\x00":
        return True  # RAR 5
    return False


def validate_gz(data: bytes) -> bool:
    """Validate GZIP archive."""
    if len(data) < 10:
        return False
    if data[:2] != b"\x1F\x8B":
        return False
    method = data[2]
    return method == 8  # deflate


def validate_bz2(data: bytes) -> bool:
    """Validate BZIP2 archive."""
    if len(data) < 10:
        return False
    if data[:3] != b"BZh":
        return False
    block_size = data[3:4]
    return block_size in (b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9")


def validate_xz(data: bytes) -> bool:
    """Validate XZ archive."""
    if len(data) < 12:
        return False
    return data[:6] == b"\xFD\x37\x7A\x58\x5A\x00"


def validate_tar(data: bytes) -> bool:
    """Validate TAR archive — check ustar magic at offset 257."""
    if len(data) < 512:
        return False
    return data[257:262] in (b"ustar", b"ustar")


def validate_cab(data: bytes) -> bool:
    """Validate CAB (Microsoft Cabinet)."""
    if len(data) < 36:
        return False
    if data[:4] != b"MSCF":
        return False
    # Cabinet size at offset 8 (4 bytes LE)
    cab_size = struct.unpack("<I", data[8:12])[0]
    return 36 <= cab_size <= 2 * 1024 * 1024 * 1024  # up to 2 GB


def validate_iso(data: bytes) -> bool:
    """Validate ISO 9660 — check for CD001 at offset 32769."""
    if len(data) < 32774:
        return False
    return data[32769:32774] == b"CD001"


def validate_zstd(data: bytes) -> bool:
    """Validate Zstandard compressed data."""
    if len(data) < 8:
        return False
    return data[:4] == b"\x28\xB5\x2F\xFD"


def validate_lz4(data: bytes) -> bool:
    """Validate LZ4 frame."""
    if len(data) < 7:
        return False
    return data[:4] == b"\x04\x22\x4D\x18"


def validate_exe(data: bytes) -> bool:
    """Validate PE executable (EXE/DLL)."""
    if len(data) < 64:
        return False
    if data[:2] != b"MZ":
        return False
    # PE header offset at 0x3C (4 bytes LE)
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data):
        return True  # Accept — we can't verify but MZ header is present
    return data[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def validate_elf(data: bytes) -> bool:
    """Validate ELF binary."""
    if len(data) < 16:
        return False
    if data[:4] != b"\x7FELF":
        return False
    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]   # 1=LE, 2=BE
    return ei_class in (1, 2) and ei_data in (1, 2)


def validate_macho(data: bytes) -> bool:
    """Validate Mach-O binary."""
    if len(data) < 28:
        return False
    magic = data[:4]
    valid_magics = (
        b"\xFE\xED\xFA\xCE",  # 32-bit
        b"\xFE\xED\xFA\xCF",  # 64-bit
        b"\xCE\xFA\xED\xFE",  # 32-bit reversed
        b"\xCF\xFA\xED\xFE",  # 64-bit reversed
        b"\xCA\xFE\xBA\xBE",  # Fat/Universal
    )
    return magic in valid_magics


def validate_dex(data: bytes) -> bool:
    """Validate Android DEX bytecode."""
    if len(data) < 112:
        return False
    if data[:4] != b"dex\n":
        return False
    # Version string at offset 4-7 (e.g., "035\0" or "039\0")
    return data[7] == 0


def validate_wasm(data: bytes) -> bool:
    """Validate WebAssembly binary."""
    if len(data) < 8:
        return False
    if data[:4] != b"\x00asm":
        return False
    # Version at offset 4 (4 bytes LE), currently 1
    version = struct.unpack("<I", data[4:8])[0]
    return version == 1


def validate_ttf(data: bytes) -> bool:
    """Validate TrueType font."""
    if len(data) < 12:
        return False
    # TrueType: 0x00010000 or "true"
    magic = data[:4]
    if magic not in (b"\x00\x01\x00\x00", b"true"):
        return False
    num_tables = struct.unpack(">H", data[4:6])[0]
    return 1 <= num_tables <= 256


def validate_otf(data: bytes) -> bool:
    """Validate OpenType font with CFF outlines."""
    if len(data) < 12:
        return False
    if data[:4] != b"OTTO":
        return False
    num_tables = struct.unpack(">H", data[4:6])[0]
    return 1 <= num_tables <= 256


def validate_woff(data: bytes) -> bool:
    """Validate WOFF font."""
    if len(data) < 44:
        return False
    if data[:4] != b"wOFF":
        return False
    # Total size at offset 4 (4 bytes BE)
    total_size = struct.unpack(">I", data[4:8])[0]
    return total_size >= 44


def validate_woff2(data: bytes) -> bool:
    """Validate WOFF2 font."""
    if len(data) < 48:
        return False
    if data[:4] != b"wOF2":
        return False
    total_size = struct.unpack(">I", data[4:8])[0]
    return total_size >= 48


def validate_parquet(data: bytes) -> bool:
    """Validate Apache Parquet file."""
    if len(data) < 12:
        return False
    if data[:4] != b"PAR1":
        return False
    # Footer magic should also be PAR1 at end (if we have full file)
    if len(data) >= 8 and data[-4:] == b"PAR1":
        return True
    return True  # Accept based on header alone


def validate_hdf5(data: bytes) -> bool:
    """Validate HDF5 file."""
    if len(data) < 16:
        return False
    return data[:8] == b"\x89HDF\r\n\x1A\n"


def validate_npy(data: bytes) -> bool:
    """Validate NumPy .npy file."""
    if len(data) < 10:
        return False
    if data[:6] != b"\x93NUMPY":
        return False
    # Version at offset 6 (1 byte major, 1 byte minor)
    major = data[6]
    return major in (1, 2, 3)


def validate_pcap(data: bytes) -> bool:
    """Validate PCAP capture file."""
    if len(data) < 24:
        return False
    magic = data[:4]
    if magic not in (b"\xD4\xC3\xB2\xA1", b"\xA1\xB2\xC3\xD4"):
        return False
    # Major version at offset 4 (2 bytes)
    if magic == b"\xD4\xC3\xB2\xA1":
        major = struct.unpack("<H", data[4:6])[0]
    else:
        major = struct.unpack(">H", data[4:6])[0]
    return major == 2


def validate_pcapng(data: bytes) -> bool:
    """Validate PCAP-NG file."""
    if len(data) < 28:
        return False
    # Section Header Block magic
    return data[:4] == b"\x0A\x0D\x0D\x0A"


def validate_lnk(data: bytes) -> bool:
    """Validate Windows LNK shortcut."""
    if len(data) < 76:
        return False
    return data[:8] == b"\x4C\x00\x00\x00\x01\x14\x02\x00"


def validate_reg(data: bytes) -> bool:
    """Validate Windows Registry Hive."""
    if len(data) < 4096:
        return False
    return data[:4] == b"regf"


def validate_plist(data: bytes) -> bool:
    """Validate Apple binary plist."""
    if len(data) < 8:
        return False
    return data[:6] == b"bplist"


def validate_avro(data: bytes) -> bool:
    """Validate Apache Avro file."""
    if len(data) < 16:
        return False
    return data[:4] == b"Obj\x01"


def validate_orc(data: bytes) -> bool:
    """Validate Apache ORC file."""
    if len(data) < 4:
        return False
    return data[:3] == b"ORC"


# ══════════════════════════════════════════════════════════════
#  Validator dispatch table
# ══════════════════════════════════════════════════════════════

_VALIDATORS: dict = {
    # Images
    "jpg": validate_jpeg,
    "jpeg": validate_jpeg,
    "png": validate_png,
    "gif": validate_gif,
    "bmp": validate_bmp,
    "tiff": validate_tiff,
    "tif": validate_tiff,
    "webp": validate_webp,
    "jp2": validate_jp2,
    "psd": validate_psd,
    "ico": validate_ico,
    "raf": validate_raf,
    # TIFF-based RAW — share the TIFF validator
    "cr2": validate_tiff,
    "nef": validate_tiff,
    "arw": validate_tiff,
    "dng": validate_tiff,
    "orf": validate_tiff,
    "rw2": validate_tiff,
    # ISO Base Media
    "heic": validate_isobmff,
    "avif": validate_isobmff,
    "mp4": validate_isobmff,
    "mov": validate_isobmff,
    "3gp": validate_isobmff,
    "m4v": validate_isobmff,
    # Video
    "avi": validate_avi,
    "mkv": validate_mkv,
    "webm": validate_mkv,      # WebM uses same EBML container
    "flv": validate_flv,
    "wmv": validate_wmv,
    "asf": validate_wmv,
    "mpg": validate_mpg,
    "mpeg": validate_mpg,
    "ts": validate_ts,
    "mts": validate_ts,
    "m2ts": validate_ts,
    "vob": validate_vob,
    "ogv": validate_ogv,
    "ogg": validate_ogv,
    "rm": validate_rm,
    "rmvb": validate_rm,
    "swf": validate_swf,
    # Audio
    "mp3": validate_mp3,
    "wav": validate_wav,
    "flac": validate_flac,
    "aiff": validate_aiff,
    "aif": validate_aiff,
    "mid": validate_midi,
    "midi": validate_midi,
    "m4a": validate_isobmff,    # M4A uses ISO Base Media container
    "ogg": validate_ogv,        # OGG audio uses same container
    "wma": validate_wmv,        # WMA uses ASF container like WMV
    # Documents
    "pdf": validate_pdf,
    "zip": validate_zip,
    "docx": validate_zip,       # Office Open XML is ZIP-based
    "xlsx": validate_zip,
    "pptx": validate_zip,
    "sqlite": validate_sqlite,
    "db": validate_sqlite,
    # Documents (new)
    "rtf": validate_rtf,
    "xml": validate_xml,
    "html": validate_html,
    "htm": validate_html,
    "eps": validate_eps,
    "doc": validate_ole2,       # OLE2 compound document
    "xls": validate_ole2,
    "ppt": validate_ole2,
    "msg": validate_ole2,
    "epub": validate_zip,       # EPUB is ZIP-based
    "odt": validate_zip,        # ODF is ZIP-based
    "ods": validate_zip,
    "odp": validate_zip,
    # Archives
    "7z": validate_7z,
    "rar": validate_rar,
    "gz": validate_gz,
    "gzip": validate_gz,
    "bz2": validate_bz2,
    "xz": validate_xz,
    "tar": validate_tar,
    "cab": validate_cab,
    "iso": validate_iso,
    "zst": validate_zstd,
    "zstd": validate_zstd,
    "lz4": validate_lz4,
    # Executables
    "exe": validate_exe,
    "dll": validate_exe,
    "sys": validate_exe,
    "elf": validate_elf,
    "so": validate_elf,
    "macho": validate_macho,
    "dylib": validate_macho,
    "dex": validate_dex,
    "wasm": validate_wasm,
    # Fonts
    "ttf": validate_ttf,
    "otf": validate_otf,
    "woff": validate_woff,
    "woff2": validate_woff2,
    # Database / Data Science
    "parquet": validate_parquet,
    "avro": validate_avro,
    "orc": validate_orc,
    "hdf5": validate_hdf5,
    "h5": validate_hdf5,
    "npy": validate_npy,
    "pcap": validate_pcap,
    "pcapng": validate_pcapng,
    # System / Misc
    "lnk": validate_lnk,
    "reg": validate_reg,
    "plist": validate_plist,
}

# Extensions that are allowed to be very small (< 4 KB)
_SMALL_EXTS = {"ico"}


# Image extensions that Pillow can decode
_PILLOW_EXTS = {
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif",
    "webp", "ico", "psd", "jp2", "tga",
}


def validate_carved_file(extension: str, data: bytes) -> bool:
    """
    Validate carved file data.  Returns True if it looks like a real file.

    Uses a 3-layer approach:
      1. Size check
      2. Structural header check (fast, format-specific)
      3. Pillow deep decode (catches corrupt internal data)
    """
    ext = extension.lower()

    # Size check — use smaller threshold for ICO, etc.
    min_sz = MIN_FILE_SIZE_SMALL if ext in _SMALL_EXTS else MIN_FILE_SIZE
    if len(data) < min_sz:
        return False

    # Type-specific structural check
    validator = _VALIDATORS.get(ext)
    if validator is not None:
        if not validator(data):
            return False
    elif ext == "tga":
        # TGA has no reliable magic — accept if it passes entropy check
        pass
    else:
        # Unknown extension — accept with entropy check only
        logger.debug("No validator for .%s — using entropy check only", ext)

    # Entropy check on a sample from the middle of the file
    sample_start = min(1024, len(data) // 4)
    sample_end = min(sample_start + 4096, len(data))
    sample = data[sample_start:sample_end]
    if len(sample) >= 256:
        entropy = calculate_entropy(sample)
        if entropy < MIN_ENTROPY:
            logger.debug("Rejecting %s: entropy %.2f < %.2f",
                         ext, entropy, MIN_ENTROPY)
            return False
        if entropy > MAX_ENTROPY:
            logger.debug("Rejecting %s: entropy %.4f > %.4f",
                         ext, entropy, MAX_ENTROPY)
            return False

    # ── Pillow deep validation for image files ────────────────
    # This catches false positives where the header looks OK but
    # the actual pixel data is corrupt or garbage.
    if _HAS_PILLOW and ext in _PILLOW_EXTS:
        if not _pillow_validate(ext, data):
            return False

    return True


def _pillow_validate(ext: str, data: bytes) -> bool:
    """Try to decode image data with Pillow.  Returns False if corrupt."""
    try:
        img = _PILImage.open(io.BytesIO(data))
        # .verify() checks structural integrity without full decode
        # But some formats need .load() to catch truncation
        img.verify()
        # Re-open after verify (verify invalidates the image object)
        img = _PILImage.open(io.BytesIO(data))
        # Load a small portion to verify pixel data is readable
        # For large BMPs (>10MB) just verify header via verify()
        if len(data) < 10 * 1024 * 1024:
            img.load()
        return True
    except Exception as e:
        logger.debug("Pillow rejected %s (%d bytes): %s", ext, len(data), e)
        return False


def validate_file_data_matches_extension(ext: str, data: bytes) -> bool:
    """Check that the actual data format matches the claimed extension.

    Used by TSK save to reject files whose clusters have been overwritten.
    Returns True if the data looks like it matches *ext*.
    """
    if not data or len(data) < 4:
        return False
    ext = ext.lower()
    # Quick magic-byte check
    _MAGIC = {
        "jpg": (b"\xff\xd8\xff",),
        "jpeg": (b"\xff\xd8\xff",),
        "png": (b"\x89PNG",),
        "gif": (b"GIF87a", b"GIF89a"),
        "bmp": (b"BM",),
        "tiff": (b"II\x2a\x00", b"MM\x00\x2a"),
        "tif": (b"II\x2a\x00", b"MM\x00\x2a"),
        "webp": (b"RIFF",),
        "psd": (b"8BPS",),
        "ico": (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"),
        "mp4": None,  # check ftyp
        "mov": None,
        "avi": (b"RIFF",),
        "mkv": (b"\x1a\x45\xdf\xa3",),
        "webm": (b"\x1a\x45\xdf\xa3",),
        "flv": (b"FLV",),
        "wmv": (b"\x30\x26\xb2\x75",),
        "mpg": None,   # handled below — any MPEG start code
        "mpeg": None,  # handled below — any MPEG start code
        "3gp": None,
        "m4v": None,
        "heic": None,
        "avif": None,
        "cr2": (b"II\x2a\x00",),
        "nef": (b"MM\x00\x2a",),
        "arw": (b"II\x2a\x00",),
        "dng": (b"II\x2a\x00", b"MM\x00\x2a"),
        "jp2": (b"\x00\x00\x00\x0c\x6a\x50",),
        # Audio
        "mp3": (b"ID3", b"\xff\xfb", b"\xff\xfa", b"\xff\xf3", b"\xff\xf2"),
        "wav": (b"RIFF",),
        "flac": (b"fLaC",),
        "m4a": None,  # ftyp-based
        "aiff": (b"FORM",),
        "aif": (b"FORM",),
        "mid": (b"MThd",),
        "midi": (b"MThd",),
        "wma": (b"\x30\x26\xb2\x75",),
        "ogg": (b"OggS",),
        # Documents
        "pdf": (b"%PDF",),
        "zip": (b"PK\x03\x04",),
        "docx": (b"PK\x03\x04",),
        "xlsx": (b"PK\x03\x04",),
        "pptx": (b"PK\x03\x04",),
        "sqlite": (b"SQLite format 3",),
        # Documents (new)
        "rtf": (b"{\\rtf",),
        "xml": (b"<?xml", b"\xEF\xBB\xBF<?"),
        "html": (b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML"),
        "htm": (b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML"),
        "eps": (b"%!PS-Adobe",),
        "doc": (b"\xD0\xCF\x11\xE0",),
        "xls": (b"\xD0\xCF\x11\xE0",),
        "ppt": (b"\xD0\xCF\x11\xE0",),
        "epub": (b"PK\x03\x04",),
        "odt": (b"PK\x03\x04",),
        "ods": (b"PK\x03\x04",),
        "odp": (b"PK\x03\x04",),
        # Archives
        "7z": (b"7z\xBC\xAF\x27\x1C",),
        "rar": (b"Rar!\x1A\x07",),
        "gz": (b"\x1F\x8B",),
        "bz2": (b"BZh",),
        "xz": (b"\xFD\x37\x7A\x58\x5A\x00",),
        "tar": None,  # TAR magic at offset 257
        "cab": (b"MSCF",),
        "zst": (b"\x28\xB5\x2F\xFD",),
        "lz4": (b"\x04\x22\x4D\x18",),
        # Executables
        "exe": (b"MZ",),
        "dll": (b"MZ",),
        "elf": (b"\x7FELF",),
        "dex": (b"dex\n",),
        "wasm": (b"\x00asm",),
        # Fonts
        "ttf": (b"\x00\x01\x00\x00", b"true"),
        "otf": (b"OTTO",),
        "woff": (b"wOFF",),
        "woff2": (b"wOF2",),
        # Data/Science
        "parquet": (b"PAR1",),
        "hdf5": (b"\x89HDF\r\n",),
        "h5": (b"\x89HDF\r\n",),
        "npy": (b"\x93NUMPY",),
        "pcap": (b"\xD4\xC3\xB2\xA1", b"\xA1\xB2\xC3\xD4"),
        "pcapng": (b"\x0A\x0D\x0D\x0A",),
        # System
        "lnk": (b"\x4C\x00\x00\x00",),
        "reg": (b"regf",),
        "plist": (b"bplist",),
    }
    magics = _MAGIC.get(ext)
    if magics is None:
        # MPEG: use the full validator (accepts many start codes)
        if ext in ("mpg", "mpeg"):
            return validate_mpg(data)
        # ISO Base Media: check for ftyp at offset 4
        if ext in ("mp4", "mov", "3gp", "m4v", "heic", "avif", "m4a"):
            return len(data) >= 8 and data[4:8] == b"ftyp"
        # TAR: check for ustar at offset 257
        if ext == "tar":
            return len(data) >= 262 and data[257:262] == b"ustar"
        # ISO: check for CD001 at offset 32769
        if ext == "iso":
            return len(data) >= 32774 and data[32769:32774] == b"CD001"
        # Unknown extension — allow
        return True
    return any(data[:len(m)] == m for m in magics)


# ── Hashing ───────────────────────────────────────────────────

def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def quick_hash(data: bytes, size: int = 8192) -> str:
    """Hash of head + tail for fast dedup."""
    head = data[:size]
    tail = data[-size:] if len(data) > size else b""
    return hashlib.md5(head + tail).hexdigest()


class DeduplicationTracker:
    """Track already-recovered content to avoid duplicates."""

    def __init__(self):
        self._quick_hashes: set[str] = set()
        self._offsets: set[int] = set()

    def is_duplicate_offset(self, offset: int, window: int = 512) -> bool:
        """Check if we already carved something within ±window of this offset."""
        for o in self._offsets:
            if abs(o - offset) < window:
                return True
        return False

    def is_duplicate_content(self, data: bytes) -> bool:
        qh = quick_hash(data)
        if qh in self._quick_hashes:
            return True
        self._quick_hashes.add(qh)
        return False

    def register(self, offset: int):
        self._offsets.add(offset)

    def clear(self):
        self._quick_hashes.clear()
        self._offsets.clear()
