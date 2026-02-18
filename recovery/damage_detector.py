"""
Damage Detector — Identify damaged/corrupted recovered files.

Performs multi-level damage analysis on carved file data:
  1. Header integrity   — magic bytes, required fields, structure
  2. Footer integrity   — end-of-file markers present and correct
  3. Structural checks  — internal consistency (box sizes, chunk CRCs, etc.)
  4. Entropy analysis   — detect zeroed/wiped/garbage regions
  5. Truncation check   — file appears cut short

Damage levels:
  • "healthy"    — file passes all checks
  • "minor"      — cosmetic issues, likely still usable
  • "moderate"   — some data loss, partial recovery possible
  • "severe"     — heavy corruption, repair may recover partial data
  • "fatal"      — unrecoverable, file data completely destroyed
"""

from __future__ import annotations

import io
import struct
import logging
import math
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DamageReport:
    """Detailed report of file damage analysis."""
    is_damaged: bool = False
    damage_level: str = "healthy"       # healthy, minor, moderate, severe, fatal
    damage_score: float = 0.0           # 0.0 (perfect) to 1.0 (destroyed)
    issues: list[str] = field(default_factory=list)
    repairable: bool = False
    repair_actions: list[str] = field(default_factory=list)
    # Specific flags
    header_damaged: bool = False
    footer_missing: bool = False
    truncated: bool = False
    has_null_regions: bool = False
    structure_broken: bool = False
    entropy_anomaly: bool = False
    # Details
    expected_size: int = 0
    actual_size: int = 0
    null_region_bytes: int = 0
    null_region_percent: float = 0.0

    @property
    def status_icon(self) -> str:
        icons = {
            "healthy": "✅",
            "minor": "⚠️",
            "moderate": "🟡",
            "severe": "🔴",
            "fatal": "💀",
        }
        return icons.get(self.damage_level, "❓")

    @property
    def status_text(self) -> str:
        if not self.is_damaged:
            return "Healthy"
        return f"{self.damage_level.capitalize()} damage"

    @property
    def short_summary(self) -> str:
        if not self.is_damaged:
            return "File intact"
        parts = []
        if self.header_damaged:
            parts.append("header damaged")
        if self.footer_missing:
            parts.append("footer missing")
        if self.truncated:
            parts.append("truncated")
        if self.has_null_regions:
            parts.append(f"{self.null_region_percent:.0f}% zeroed")
        if self.structure_broken:
            parts.append("structure broken")
        return ", ".join(parts) if parts else "unknown damage"


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
#  Main entry point
# ══════════════════════════════════════════════════════════════

def analyze_damage(extension: str, data: bytes,
                   expected_size: int = 0) -> DamageReport:
    """Analyze file data for damage and corruption.

    Args:
        extension: File extension (e.g., "jpg", "png", "mp4")
        data: Raw file bytes
        expected_size: Expected file size (0 if unknown)

    Returns:
        DamageReport with detailed findings
    """
    report = DamageReport()
    report.actual_size = len(data)
    report.expected_size = expected_size or len(data)

    if not data or len(data) < 8:
        report.is_damaged = True
        report.damage_level = "fatal"
        report.damage_score = 1.0
        report.issues.append("File is empty or too small")
        return report

    ext = extension.lower()

    # 1. Header check
    _check_header(ext, data, report)

    # 2. Footer check
    _check_footer(ext, data, report)

    # 3. Null/zeroed region detection
    _check_null_regions(data, report)

    # 4. Structural integrity
    _check_structure(ext, data, report)

    # 5. Truncation detection
    _check_truncation(ext, data, expected_size, report)

    # 6. Entropy anomalies
    _check_entropy(ext, data, report)

    # Calculate overall score and level
    _compute_damage_level(report)

    # Determine repairability
    _assess_repairability(ext, report)

    return report


# ══════════════════════════════════════════════════════════════
#  Header checks
# ══════════════════════════════════════════════════════════════

_MAGIC_BYTES = {
    "jpg": (b"\xFF\xD8\xFF",),
    "jpeg": (b"\xFF\xD8\xFF",),
    "png": (b"\x89PNG\r\n\x1A\n",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "tiff": (b"II\x2A\x00", b"MM\x00\x2A"),
    "tif": (b"II\x2A\x00", b"MM\x00\x2A"),
    "webp": (b"RIFF",),
    "psd": (b"8BPS",),
    "ico": (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"),
    "jp2": (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A",),
    "raf": (b"FUJIFILMCCD-RAW",),
    "mp4": None,   # ftyp-based
    "mov": None,
    "heic": None,
    "avif": None,
    "3gp": None,
    "m4v": None,
    "avi": (b"RIFF",),
    "mkv": (b"\x1A\x45\xDF\xA3",),
    "webm": (b"\x1A\x45\xDF\xA3",),
    "flv": (b"FLV",),
    "wmv": (b"\x30\x26\xB2\x75\x8E\x66\xCF\x11",),
    "mpg": (b"\x00\x00\x01\xBA", b"\x00\x00\x01\xB3"),
    "mpeg": (b"\x00\x00\x01\xBA", b"\x00\x00\x01\xB3"),
    "cr2": (b"II\x2A\x00",),
    "nef": (b"MM\x00\x2A",),
    "arw": (b"II\x2A\x00",),
    "dng": (b"II\x2A\x00", b"MM\x00\x2A"),
}

_FTYP_EXTENSIONS = {"mp4", "mov", "heic", "avif", "3gp", "m4v"}


def _check_header(ext: str, data: bytes, report: DamageReport):
    """Check if the file header magic bytes are correct."""
    if ext in _FTYP_EXTENSIONS:
        # ISO Base Media: look for ftyp box
        if len(data) >= 8 and data[4:8] == b"ftyp":
            try:
                box_size = struct.unpack(">I", data[:4])[0]
                if box_size < 8 or box_size > 4096:
                    report.header_damaged = True
                    report.issues.append(f"Invalid ftyp box size: {box_size}")
            except struct.error:
                report.header_damaged = True
                report.issues.append("Cannot read ftyp box header")
        else:
            report.header_damaged = True
            report.issues.append("Missing ftyp box — ISO BMFF header damaged")
            report.repair_actions.append("reconstruct_ftyp_header")
        return

    magics = _MAGIC_BYTES.get(ext)
    if magics is None:
        return  # Unknown extension

    for magic in magics:
        if data[:len(magic)] == magic:
            # Further header-specific checks
            if ext in ("jpg", "jpeg"):
                if len(data) >= 4 and data[2] == 0xFF:
                    m = data[3]
                    if m < 0xC0 or (0xD0 <= m <= 0xD7):
                        report.header_damaged = True
                        report.issues.append(
                            f"Invalid JPEG marker 0x{m:02X} after SOI")
                        report.repair_actions.append("fix_jpeg_marker")
            elif ext == "png":
                if len(data) >= 16 and data[12:16] != b"IHDR":
                    report.header_damaged = True
                    report.issues.append("PNG: first chunk is not IHDR")
                    report.repair_actions.append("fix_png_ihdr")
            return

    # Header doesn't match any known magic
    report.header_damaged = True
    report.issues.append(f"Header magic bytes corrupted for .{ext}")
    report.repair_actions.append(f"reconstruct_{ext}_header")


# ══════════════════════════════════════════════════════════════
#  Footer checks
# ══════════════════════════════════════════════════════════════

_FOOTERS = {
    "jpg": b"\xFF\xD9",
    "jpeg": b"\xFF\xD9",
    "png": b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82",
    "gif": b"\x00\x3B",
    "mpg": b"\x00\x00\x01\xB9",
    "mpeg": b"\x00\x00\x01\xB9",
}


def _check_footer(ext: str, data: bytes, report: DamageReport):
    """Check if the file has its expected end-of-file marker."""
    footer = _FOOTERS.get(ext.lower())
    if footer is None:
        return  # Not a footer-based format

    # Search in the last portion of the file
    tail_size = min(len(data), 4096)
    tail = data[-tail_size:]

    if ext.lower() in ("jpg", "jpeg"):
        pos = tail.rfind(footer)
    else:
        pos = tail.rfind(footer)

    if pos == -1:
        report.footer_missing = True
        report.issues.append(f"Missing {ext.upper()} end-of-file marker")
        report.repair_actions.append(f"append_{ext}_footer")


# ══════════════════════════════════════════════════════════════
#  Null region detection
# ══════════════════════════════════════════════════════════════

def _check_null_regions(data: bytes, report: DamageReport):
    """Detect large null (zeroed-out) regions within the file."""
    if len(data) < 1024:
        return

    block_size = 4096
    null_bytes = 0
    total_checked = 0

    # Skip the first 512 bytes (header area) and last 512 bytes (footer area)
    start = min(512, len(data) // 4)
    end = max(start + block_size, len(data) - 512)

    for i in range(start, end, block_size):
        block = data[i:i + block_size]
        total_checked += len(block)
        zero_count = block.count(0)
        if zero_count > len(block) * 0.95:
            null_bytes += len(block)

    if total_checked > 0:
        report.null_region_bytes = null_bytes
        report.null_region_percent = (null_bytes / total_checked) * 100

        if report.null_region_percent > 50:
            report.has_null_regions = True
            report.issues.append(
                f"{report.null_region_percent:.0f}% of file data is zeroed "
                f"(likely TRIM'd or overwritten)")
        elif report.null_region_percent > 20:
            report.has_null_regions = True
            report.issues.append(
                f"{report.null_region_percent:.0f}% of file data is zeroed "
                f"(partial overwrite)")


# ══════════════════════════════════════════════════════════════
#  Structural integrity checks
# ══════════════════════════════════════════════════════════════

def _check_structure(ext: str, data: bytes, report: DamageReport):
    """Check internal file structure for consistency."""
    ext = ext.lower()

    if ext in ("jpg", "jpeg"):
        _check_jpeg_structure(data, report)
    elif ext == "png":
        _check_png_structure(data, report)
    elif ext in _FTYP_EXTENSIONS:
        _check_isobmff_structure(data, report)
    elif ext == "bmp":
        _check_bmp_structure(data, report)
    elif ext in ("avi", "webp"):
        _check_riff_structure(data, report)
    elif ext in ("mpg", "mpeg", "vob"):
        _check_mpeg_ps_structure(data, report)
    elif ext == "swf":
        _check_swf_structure(data, report)


def _check_jpeg_structure(data: bytes, report: DamageReport):
    """Walk JPEG markers to check structural integrity."""
    if len(data) < 4 or data[:2] != b"\xFF\xD8":
        return

    pos = 2
    marker_count = 0
    has_sos = False
    has_sof = False

    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            # Not at a marker — in entropy-coded data after SOS
            if has_sos:
                break
            # Unexpected byte before SOS marker
            report.structure_broken = True
            report.issues.append(
                f"JPEG: unexpected byte 0x{data[pos]:02X} at offset {pos}")
            report.repair_actions.append("repair_jpeg_markers")
            break

        # Skip padding FF bytes
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break

        marker = data[pos]
        pos += 1
        marker_count += 1

        # EOI
        if marker == 0xD9:
            break

        # SOS — start of scan (entropy-coded data follows)
        if marker == 0xDA:
            has_sos = True
            if pos + 2 <= len(data):
                seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += seg_len
            break

        # SOF markers (0xC0-0xCF except 0xC4, 0xC8, 0xCC)
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            has_sof = True

        # Skip standalone markers (RST, TEM)
        if (0xD0 <= marker <= 0xD7) or marker == 0x01:
            continue

        # Read segment length
        if pos + 2 > len(data):
            report.structure_broken = True
            report.issues.append("JPEG: truncated marker segment")
            break
        seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
        if seg_len < 2:
            report.structure_broken = True
            report.issues.append(
                f"JPEG: invalid segment length {seg_len} at marker 0xFF{marker:02X}")
            report.repair_actions.append("repair_jpeg_markers")
            break
        pos += seg_len

    if marker_count > 0 and not has_sof and not report.structure_broken:
        report.structure_broken = True
        report.issues.append("JPEG: no SOF (Start of Frame) marker found")


def _check_png_structure(data: bytes, report: DamageReport):
    """Walk PNG chunks and validate CRCs."""
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1A\n":
        return

    import zlib
    pos = 8
    chunk_count = 0
    has_iend = False
    has_idat = False
    bad_crcs = 0

    while pos + 12 <= len(data):
        chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        pos += 8

        if chunk_len > len(data) - pos:
            report.structure_broken = True
            report.issues.append(
                f"PNG: chunk '{chunk_type.decode('ascii', errors='replace')}' "
                f"claims {chunk_len} bytes but only {len(data) - pos} remain")
            report.repair_actions.append("repair_png_chunks")
            break

        chunk_data = data[pos:pos + chunk_len]
        pos += chunk_len

        if pos + 4 > len(data):
            report.structure_broken = True
            report.issues.append("PNG: missing CRC for chunk")
            break

        stored_crc = struct.unpack(">I", data[pos:pos + 4])[0]
        computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        pos += 4

        if stored_crc != computed_crc:
            bad_crcs += 1
            if bad_crcs <= 3:
                report.issues.append(
                    f"PNG: CRC mismatch in "
                    f"'{chunk_type.decode('ascii', errors='replace')}' chunk")
                report.repair_actions.append("fix_png_crcs")

        if chunk_type == b"IDAT":
            has_idat = True
        if chunk_type == b"IEND":
            has_iend = True
            break

        chunk_count += 1
        if chunk_count > 10000:
            break

    if bad_crcs > 0:
        report.structure_broken = True
        report.issues.append(f"PNG: {bad_crcs} chunk(s) with CRC errors")

    if not has_idat and not report.structure_broken:
        report.structure_broken = True
        report.issues.append("PNG: no IDAT (image data) chunks found")

    if not has_iend:
        report.footer_missing = True
        if "Missing PNG end-of-file marker" not in report.issues:
            report.issues.append("PNG: missing IEND chunk")
            report.repair_actions.append("append_png_iend")


def _check_isobmff_structure(data: bytes, report: DamageReport):
    """Walk ISO Base Media boxes and check for consistency."""
    if len(data) < 8:
        return

    KNOWN = {
        b"ftyp", b"moov", b"mdat", b"free", b"skip",
        b"wide", b"meta", b"moof", b"mfra", b"styp",
        b"sidx", b"ssix", b"pdin", b"uuid",
    }

    pos = 0
    has_moov = False
    has_mdat = False
    box_count = 0

    while pos + 8 <= len(data):
        box_size = struct.unpack(">I", data[pos:pos + 4])[0]
        box_type = data[pos + 4:pos + 8]

        if box_size == 1 and pos + 16 <= len(data):
            box_size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]

        if box_size < 8:
            if box_count == 0:
                report.structure_broken = True
                report.issues.append("ISO BMFF: first box has invalid size")
            break

        if box_type == b"moov":
            has_moov = True
        if box_type == b"mdat":
            has_mdat = True

        if box_type not in KNOWN and box_count > 0:
            # Unknown box type could indicate corruption at this point
            try:
                type_str = box_type.decode("ascii", errors="replace")
                if not all(32 <= ord(c) < 127 for c in type_str):
                    report.structure_broken = True
                    report.issues.append(
                        f"ISO BMFF: invalid box type at offset {pos}")
                    break
            except Exception:
                report.structure_broken = True
                break

        pos += box_size
        box_count += 1
        if box_count > 10000:
            break

    if box_count > 0 and not has_moov:
        report.structure_broken = True
        report.issues.append(
            "ISO BMFF: missing 'moov' box (metadata lost — video may not play)")
        report.repair_actions.append("repair_moov_box")

    if box_count > 0 and not has_mdat and not report.structure_broken:
        report.issues.append("ISO BMFF: no 'mdat' box (media data missing)")


def _check_bmp_structure(data: bytes, report: DamageReport):
    """Check BMP header fields for consistency."""
    if len(data) < 54 or data[:2] != b"BM":
        return

    file_size = struct.unpack("<I", data[2:6])[0]
    data_off = struct.unpack("<I", data[10:14])[0]

    if file_size > 0 and abs(file_size - len(data)) > 1024:
        report.structure_broken = True
        report.issues.append(
            f"BMP: declared size {file_size} vs actual {len(data)}")
        report.repair_actions.append("fix_bmp_size_field")

    if data_off > len(data):
        report.structure_broken = True
        report.issues.append(
            f"BMP: data offset {data_off} beyond file end")


def _check_riff_structure(data: bytes, report: DamageReport):
    """Check RIFF container size field."""
    if len(data) < 12 or data[:4] != b"RIFF":
        return

    riff_size = struct.unpack("<I", data[4:8])[0]
    expected_total = riff_size + 8

    if expected_total > 0 and abs(expected_total - len(data)) > 4096:
        report.structure_broken = True
        report.issues.append(
            f"RIFF: declared size {expected_total} vs actual {len(data)}")
        report.repair_actions.append("fix_riff_size_field")


def _check_mpeg_ps_structure(data: bytes, report: DamageReport):
    """Analyze MPEG Program Stream structure for damage."""
    if len(data) < 12:
        return

    _START_PREFIX = b"\x00\x00\x01"
    _VALID_CODES = set(range(0x00, 0xBA)) | {
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
    } | set(range(0xC0, 0xF0))

    # Count valid start codes
    start_code_count = 0
    pack_count = 0
    has_seq_header = False
    has_gop = False
    has_end_code = False
    max_gap = 0
    prev_sc_pos = 0

    # Sample start codes (don't scan entire multi-GB file)
    sample_size = min(len(data), 10 * 1024 * 1024)  # First 10 MB
    pos = 0
    while pos < sample_size - 4:
        idx = data[pos:sample_size].find(_START_PREFIX)
        if idx == -1:
            break
        abs_pos = pos + idx
        if abs_pos + 3 >= len(data):
            break
        code = data[abs_pos + 3]
        if code in _VALID_CODES:
            start_code_count += 1
            gap = abs_pos - prev_sc_pos
            if gap > max_gap and start_code_count > 1:
                max_gap = gap
            prev_sc_pos = abs_pos

            if code == 0xBA:
                pack_count += 1
            elif code == 0xB3:
                has_seq_header = True
            elif code == 0xB8:
                has_gop = True
            elif code == 0xB9:
                has_end_code = True
        pos = abs_pos + 1

    # Also check for end code at the very end
    if data[-4:] == b"\x00\x00\x01\xB9":
        has_end_code = True

    # Assess structural integrity
    if start_code_count == 0:
        report.structure_broken = True
        report.issues.append("MPEG-PS: no valid start codes found")
        return

    if pack_count == 0 and not has_seq_header:
        report.structure_broken = True
        report.issues.append(
            "MPEG-PS: no pack headers or sequence headers found")
        report.repair_actions.append("reconstruct_mpeg_header")

    # Large gaps between start codes indicate zeroed/missing sections
    if max_gap > 1024 * 1024:  # >1MB gap
        report.structure_broken = True
        report.issues.append(
            f"MPEG-PS: large gap ({max_gap:,} bytes) between start codes "
            f"(data may be zeroed/missing)")
        report.repair_actions.append("excise_null_regions")

    if not has_end_code:
        if "Missing MPG end-of-file marker" not in report.issues:
            report.repair_actions.append("append_mpeg_end_code")

    # Compute density of start codes as quality metric
    if sample_size > 0:
        sc_density = start_code_count / (sample_size / (64 * 1024))
        # A healthy MPG has many start codes per 64KB
        if sc_density < 1.0 and start_code_count > 0:
            report.issues.append(
                f"MPEG-PS: low start code density ({sc_density:.1f} per 64KB) "
                f"— stream may have large corrupted sections")


def _check_swf_structure(data: bytes, report: DamageReport):
    """Check SWF file structure."""
    if len(data) < 8:
        return
    if data[:3] not in (b"FWS", b"CWS", b"ZWS"):
        return

    declared_size = struct.unpack("<I", data[4:8])[0]
    if declared_size > 0 and abs(declared_size - len(data)) > 4096:
        report.structure_broken = True
        report.issues.append(
            f"SWF: declared size {declared_size:,} vs actual {len(data):,}")
        report.repair_actions.append("fix_swf_size_field")


# ══════════════════════════════════════════════════════════════
#  Truncation detection
# ══════════════════════════════════════════════════════════════

def _check_truncation(ext: str, data: bytes,
                      expected_size: int, report: DamageReport):
    """Detect if the file is truncated."""
    ext = ext.lower()

    # Size mismatch
    if expected_size > 0 and len(data) < expected_size:
        deficit = expected_size - len(data)
        pct = (deficit / expected_size) * 100
        if pct > 5:
            report.truncated = True
            report.issues.append(
                f"File truncated: {len(data)} of {expected_size} bytes "
                f"({pct:.0f}% missing)")

    # Check for abrupt ending
    if ext in ("jpg", "jpeg"):
        # JPEG should end with FF D9
        if len(data) > 100:
            tail = data[-2:]
            if tail != b"\xFF\xD9":
                # Check if there's FF D9 somewhere close to the end
                last_ffd9 = data.rfind(b"\xFF\xD9")
                if last_ffd9 == -1:
                    report.truncated = True
                    if "truncated" not in " ".join(report.issues).lower():
                        report.issues.append(
                            "JPEG appears truncated (no EOI marker)")
                        report.repair_actions.append("append_jpeg_eoi")

    elif ext == "png":
        if b"IEND" not in data[-32:] and not report.footer_missing:
            report.truncated = True
            if "truncated" not in " ".join(report.issues).lower():
                report.issues.append("PNG appears truncated (no IEND)")
                report.repair_actions.append("append_png_iend")


# ══════════════════════════════════════════════════════════════
#  Entropy analysis
# ══════════════════════════════════════════════════════════════

def _check_entropy(ext: str, data: bytes, report: DamageReport):
    """Check for entropy anomalies in file data."""
    if len(data) < 1024:
        return

    ext = ext.lower()

    # Sample multiple regions
    regions = []
    chunk_size = 4096
    step = max(chunk_size, len(data) // 8)

    for i in range(0, len(data) - chunk_size, step):
        e = calculate_entropy(data[i:i + chunk_size])
        regions.append((i, e))

    if not regions:
        return

    entropies = [e for _, e in regions]
    avg_entropy = sum(entropies) / len(entropies)

    # Skip header region for anomaly checks
    body_entropies = [e for offset, e in regions if offset > 512]
    if not body_entropies:
        return

    # Check for sudden drops to near-zero entropy (zeroed regions)
    low_entropy_count = sum(1 for e in body_entropies if e < 0.5)
    if low_entropy_count > len(body_entropies) * 0.3:
        report.entropy_anomaly = True
        report.issues.append(
            f"Entropy anomaly: {low_entropy_count}/{len(body_entropies)} "
            f"regions have near-zero entropy (data wiped)")

    # For compressed formats, check if entropy drops suddenly
    # (indicates boundary between real data and garbage)
    compressed_exts = {"jpg", "jpeg", "png", "mp4", "mov", "heic",
                       "mkv", "webm", "flv", "3gp", "m4v",
                       "mpg", "mpeg", "vob"}
    if ext in compressed_exts and len(body_entropies) >= 4:
        # Look for a sharp transition from high to low entropy
        for i in range(1, len(body_entropies)):
            if body_entropies[i - 1] > 6.0 and body_entropies[i] < 2.0:
                offset = regions[i + (len(regions) - len(body_entropies))][0]
                report.entropy_anomaly = True
                report.issues.append(
                    f"Entropy drop at offset {offset:#x} — "
                    f"possible data corruption boundary")
                break


# ══════════════════════════════════════════════════════════════
#  Scoring and level computation
# ══════════════════════════════════════════════════════════════

def _compute_damage_level(report: DamageReport):
    """Compute overall damage score and level from individual flags."""
    score = 0.0

    if report.header_damaged:
        score += 0.35
    if report.footer_missing:
        score += 0.10
    if report.truncated:
        score += 0.15
    if report.structure_broken:
        score += 0.25
    if report.has_null_regions:
        # Scale by how much is zeroed
        score += min(0.40, report.null_region_percent / 100 * 0.5)
    if report.entropy_anomaly:
        score += 0.10

    # Bonus: multiple issues compound
    issue_count = sum([
        report.header_damaged, report.footer_missing,
        report.truncated, report.structure_broken,
        report.has_null_regions, report.entropy_anomaly,
    ])
    if issue_count >= 3:
        score += 0.10

    report.damage_score = min(1.0, score)
    report.is_damaged = score > 0.0

    if score == 0:
        report.damage_level = "healthy"
    elif score <= 0.15:
        report.damage_level = "minor"
    elif score <= 0.35:
        report.damage_level = "moderate"
    elif score <= 0.65:
        report.damage_level = "severe"
    else:
        report.damage_level = "fatal"


# ══════════════════════════════════════════════════════════════
#  Repairability assessment
# ══════════════════════════════════════════════════════════════

def _assess_repairability(ext: str, report: DamageReport):
    """Determine if the damage is repairable."""
    if not report.is_damaged:
        report.repairable = False
        return

    # MPEG-PS files are repairable even with high null regions
    # because null blocks can be surgically excised
    if ext in ("mpg", "mpeg", "vob"):
        if report.null_region_percent > 98:
            # Almost entirely zeroed — not enough data
            report.repairable = False
            return
        # MPEG files are repairable if we have at least some valid data
        report.repairable = True
        if "excise_null_regions" not in report.repair_actions:
            if report.has_null_regions:
                report.repair_actions.append("excise_null_regions")
        if "append_mpeg_end_code" not in report.repair_actions:
            if report.footer_missing:
                report.repair_actions.append("append_mpeg_end_code")
        if report.header_damaged:
            if "reconstruct_mpeg_header" not in report.repair_actions:
                report.repair_actions.append("reconstruct_mpeg_header")
        return

    # SWF files are generally repairable
    if ext == "swf":
        report.repairable = True
        if report.structure_broken:
            report.repair_actions.append("fix_swf_size_field")
        return

    if report.damage_level == "fatal":
        # Fatal damage with >60% null is not repairable
        if report.null_region_percent > 60:
            report.repairable = False
            return

    # If we have repair actions, it's potentially repairable
    if report.repair_actions:
        report.repairable = True
        return

    # Minor footer/truncation issues are usually repairable
    if report.footer_missing and not report.header_damaged:
        report.repairable = True
        report.repair_actions.append(f"append_{ext}_footer")
        return

    if report.truncated and not report.header_damaged:
        report.repairable = True
        return

    report.repairable = report.damage_score < 0.65
