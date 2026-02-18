"""
File Repair Engine — Attempt to repair damaged recovered files.

Repair strategies by format:
  • JPEG:  Fix/reconstruct header markers, append EOI (FF D9),
           remove corrupted marker segments
  • PNG:   Fix CRC errors, append IEND chunk, reconstruct IHDR
  • BMP:   Fix file size and data offset fields
  • ISO BMFF (MP4/MOV/HEIC): Fix box sizes, reconstruct ftyp header
  • RIFF (AVI/WebP): Fix RIFF size field

General repairs:
  • Trim trailing garbage/null bytes
  • Strip corrupted data beyond last valid structure

Integrity Verification:
  • Post-repair validation using the same damage analyzer
  • MD5 checksum of repaired data
  • File readback verification after save
"""

from __future__ import annotations

import io
import os
import struct
import hashlib
import logging
import zlib
from dataclasses import dataclass, field
from typing import Optional

from .damage_detector import DamageReport, analyze_damage

logger = logging.getLogger(__name__)


@dataclass
class RepairResult:
    """Result of a file repair attempt."""
    success: bool = False
    repaired_data: Optional[bytes] = None
    original_size: int = 0
    repaired_size: int = 0
    actions_taken: list[str] = field(default_factory=list)
    actions_failed: list[str] = field(default_factory=list)
    damage_before: Optional[DamageReport] = None
    damage_after: Optional[DamageReport] = None
    # Post-repair validation
    md5_before: str = ""
    md5_after: str = ""

    @property
    def size_change(self) -> int:
        return self.repaired_size - self.original_size

    @property
    def summary(self) -> str:
        if not self.success:
            return "Repair failed"
        parts = []
        if self.actions_taken:
            parts.append(f"Fixed: {', '.join(self.actions_taken)}")
        if self.size_change != 0:
            sign = "+" if self.size_change > 0 else ""
            parts.append(f"Size: {sign}{self.size_change} bytes")
        return " | ".join(parts) if parts else "No changes needed"


@dataclass
class IntegrityCheck:
    """Result of post-save integrity verification."""
    passed: bool = False
    file_path: str = ""
    expected_md5: str = ""
    actual_md5: str = ""
    expected_size: int = 0
    actual_size: int = 0
    is_readable: bool = False
    format_valid: bool = False
    issues: list[str] = field(default_factory=list)

    @property
    def status_icon(self) -> str:
        return "✅" if self.passed else "❌"

    @property
    def summary(self) -> str:
        if self.passed:
            return f"Verified OK (MD5: {self.actual_md5[:12]}…)"
        return f"FAILED: {', '.join(self.issues)}"


# ══════════════════════════════════════════════════════════════
#  Main Repair Entry Point
# ══════════════════════════════════════════════════════════════

def repair_file(extension: str, data: bytes,
                damage_report: Optional[DamageReport] = None) -> RepairResult:
    """Attempt to repair damaged file data.

    Args:
        extension: File extension (e.g., "jpg", "png")
        data: Raw file bytes
        damage_report: Pre-computed damage report (computed if None)

    Returns:
        RepairResult with repaired data and details
    """
    result = RepairResult()
    result.original_size = len(data)
    result.md5_before = hashlib.md5(data).hexdigest()

    if not data:
        result.actions_failed.append("Empty file — nothing to repair")
        return result

    ext = extension.lower()

    # Get or compute damage report
    if damage_report is None:
        damage_report = analyze_damage(ext, data)
    result.damage_before = damage_report

    if not damage_report.is_damaged:
        result.success = True
        result.repaired_data = data
        result.repaired_size = len(data)
        result.md5_after = result.md5_before
        result.actions_taken.append("No repair needed")
        return result

    # Work on a mutable copy
    repaired = bytearray(data)

    # Apply format-specific repairs
    if ext in ("jpg", "jpeg"):
        repaired = _repair_jpeg(repaired, damage_report, result)
    elif ext == "png":
        repaired = _repair_png(repaired, damage_report, result)
    elif ext == "bmp":
        repaired = _repair_bmp(repaired, damage_report, result)
    elif ext in ("mp4", "mov", "heic", "avif", "3gp", "m4v"):
        repaired = _repair_isobmff(repaired, damage_report, result)
    elif ext in ("avi", "webp"):
        repaired = _repair_riff(repaired, damage_report, result)
    elif ext == "gif":
        repaired = _repair_gif(repaired, damage_report, result)
    elif ext in ("mpg", "mpeg", "vob"):
        repaired = _repair_mpeg_ps(repaired, damage_report, result)
    elif ext == "swf":
        repaired = _repair_swf(repaired, damage_report, result)
    else:
        # Generic: trim trailing nulls
        repaired = _repair_generic(repaired, damage_report, result)

    # Finalize
    result.repaired_data = bytes(repaired)
    result.repaired_size = len(repaired)
    result.md5_after = hashlib.md5(result.repaired_data).hexdigest()

    # Validate the repair
    result.damage_after = analyze_damage(ext, result.repaired_data)

    # Success if damage level improved
    level_order = {"healthy": 0, "minor": 1, "moderate": 2,
                   "severe": 3, "fatal": 4}
    before_level = level_order.get(damage_report.damage_level, 4)
    after_level = level_order.get(result.damage_after.damage_level, 4)

    result.success = after_level < before_level or (
        result.actions_taken and not result.actions_failed
    )

    return result


# ══════════════════════════════════════════════════════════════
#  JPEG Repair
# ══════════════════════════════════════════════════════════════

def _repair_jpeg(data: bytearray, report: DamageReport,
                 result: RepairResult) -> bytearray:
    """Repair JPEG file damage."""

    # Fix header if corrupted
    if report.header_damaged:
        if len(data) >= 2 and data[:2] != b"\xFF\xD8":
            # Try to find FF D8 FF near the start
            idx = bytes(data[:512]).find(b"\xFF\xD8\xFF")
            if idx > 0:
                data = data[idx:]
                result.actions_taken.append(
                    f"Trimmed {idx} garbage bytes before SOI")
            else:
                # Reconstruct SOI
                if data[0] != 0xFF:
                    data[0] = 0xFF
                if data[1] != 0xD8:
                    data[1] = 0xD8
                result.actions_taken.append("Reconstructed JPEG SOI marker")
        elif len(data) >= 4 and data[:2] == b"\xFF\xD8":
            # SOI OK but next marker damaged
            if data[2] != 0xFF:
                data[2] = 0xFF
                result.actions_taken.append("Fixed byte after SOI")
            if len(data) >= 4:
                m = data[3]
                if m < 0xC0 or (0xD0 <= m <= 0xD7):
                    # Replace with JFIF APP0 marker
                    data[3] = 0xE0
                    result.actions_taken.append(
                        f"Replaced invalid marker 0x{m:02X} with APP0")

    # Append EOI if missing
    if report.footer_missing or report.truncated:
        # Check if EOI already exists
        if not data or data[-2:] != b"\xFF\xD9":
            # Trim trailing null bytes first
            end = len(data)
            while end > 2 and data[end - 1] == 0x00:
                end -= 1
            data = data[:end]

            # Append EOI
            data.extend(b"\xFF\xD9")
            result.actions_taken.append("Appended JPEG EOI marker (FF D9)")

    # Trim data after the last valid EOI
    last_eoi = bytes(data).rfind(b"\xFF\xD9")
    if last_eoi != -1 and last_eoi < len(data) - 2:
        trailing = len(data) - (last_eoi + 2)
        if trailing > 16:
            data = data[:last_eoi + 2]
            result.actions_taken.append(
                f"Trimmed {trailing} bytes after EOI marker")

    return data


# ══════════════════════════════════════════════════════════════
#  PNG Repair
# ══════════════════════════════════════════════════════════════

def _repair_png(data: bytearray, report: DamageReport,
                result: RepairResult) -> bytearray:
    """Repair PNG file damage."""

    # Fix header
    if report.header_damaged:
        png_sig = b"\x89PNG\r\n\x1A\n"
        if data[:8] != png_sig:
            idx = bytes(data[:512]).find(png_sig)
            if idx > 0:
                data = data[idx:]
                result.actions_taken.append(
                    f"Trimmed {idx} bytes before PNG signature")
            else:
                data[:8] = bytearray(png_sig)
                result.actions_taken.append("Reconstructed PNG signature")

    # Fix CRC errors
    if report.structure_broken and "CRC" in " ".join(report.issues):
        fixed_crcs = _fix_png_crcs(data)
        if fixed_crcs > 0:
            result.actions_taken.append(
                f"Fixed {fixed_crcs} PNG chunk CRC(s)")

    # Append IEND if missing
    if report.footer_missing or (
            report.truncated and b"IEND" not in data[-32:]):
        iend_chunk = b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82"
        if bytes(data[-12:]) != iend_chunk:
            # Trim trailing nulls
            end = len(data)
            while end > 8 and data[end - 1] == 0x00:
                end -= 1
            data = data[:end]
            data.extend(iend_chunk)
            result.actions_taken.append("Appended PNG IEND chunk")

    return data


def _fix_png_crcs(data: bytearray) -> int:
    """Recompute and fix all PNG chunk CRCs. Returns count of fixes."""
    if len(data) < 8:
        return 0

    fixed = 0
    pos = 8  # After PNG signature

    while pos + 12 <= len(data):
        if pos + 4 > len(data):
            break
        chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
        if pos + 8 > len(data):
            break
        chunk_type = bytes(data[pos + 4:pos + 8])
        pos += 8

        if chunk_len > len(data) - pos:
            break

        chunk_data = bytes(data[pos:pos + chunk_len])
        pos += chunk_len

        if pos + 4 > len(data):
            break

        stored_crc = struct.unpack(">I", data[pos:pos + 4])[0]
        correct_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        if stored_crc != correct_crc:
            struct.pack_into(">I", data, pos, correct_crc)
            fixed += 1

        pos += 4

        if chunk_type == b"IEND":
            break

    return fixed


# ══════════════════════════════════════════════════════════════
#  BMP Repair
# ══════════════════════════════════════════════════════════════

def _repair_bmp(data: bytearray, report: DamageReport,
                result: RepairResult) -> bytearray:
    """Repair BMP file damage."""

    if len(data) < 54:
        result.actions_failed.append("BMP too small to repair")
        return data

    # Fix file size field
    if report.structure_broken:
        declared_size = struct.unpack("<I", data[2:6])[0]
        if declared_size != len(data):
            struct.pack_into("<I", data, 2, len(data))
            result.actions_taken.append(
                f"Fixed BMP size field: {declared_size} → {len(data)}")

    # Fix data offset
    data_off = struct.unpack("<I", data[10:14])[0]
    if data_off > len(data):
        dib_sz = struct.unpack("<I", data[14:18])[0]
        correct_off = 14 + dib_sz
        struct.pack_into("<I", data, 10, correct_off)
        result.actions_taken.append(
            f"Fixed BMP data offset: {data_off} → {correct_off}")

    return data


# ══════════════════════════════════════════════════════════════
#  ISO BMFF (MP4/MOV/HEIC) Repair
# ══════════════════════════════════════════════════════════════

def _repair_isobmff(data: bytearray, report: DamageReport,
                    result: RepairResult) -> bytearray:
    """Repair ISO Base Media Format files."""

    # Fix ftyp header if missing
    if report.header_damaged and (len(data) < 8 or data[4:8] != b"ftyp"):
        # Try to find ftyp box nearby
        idx = bytes(data[:1024]).find(b"ftyp")
        if idx >= 4:
            box_start = idx - 4
            data = data[box_start:]
            result.actions_taken.append(
                f"Aligned to ftyp box at offset {box_start}")
        else:
            result.actions_failed.append(
                "Cannot find ftyp box — header reconstruction not possible")
            return data

    # Validate and fix box sizes
    if report.structure_broken:
        pos = 0
        last_valid_end = 0
        while pos + 8 <= len(data):
            box_size = struct.unpack(">I", data[pos:pos + 4])[0]
            box_type = bytes(data[pos + 4:pos + 8])

            if box_size == 1 and pos + 16 <= len(data):
                box_size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]

            if box_size < 8:
                break

            # If box extends beyond file, truncate its size
            if pos + box_size > len(data):
                actual_remaining = len(data) - pos
                struct.pack_into(">I", data, pos, actual_remaining)
                result.actions_taken.append(
                    f"Truncated '{box_type.decode('ascii', errors='?')}' "
                    f"box size to {actual_remaining}")
                last_valid_end = len(data)
                break

            last_valid_end = pos + box_size
            pos += box_size

        # Trim garbage after last valid box
        if last_valid_end > 0 and last_valid_end < len(data):
            trailing = len(data) - last_valid_end
            if trailing > 64:
                data = data[:last_valid_end]
                result.actions_taken.append(
                    f"Trimmed {trailing} bytes after last ISO box")

    return data


# ══════════════════════════════════════════════════════════════
#  RIFF (AVI/WebP) Repair
# ══════════════════════════════════════════════════════════════

def _repair_riff(data: bytearray, report: DamageReport,
                 result: RepairResult) -> bytearray:
    """Repair RIFF container files."""

    if len(data) < 12:
        result.actions_failed.append("RIFF too small to repair")
        return data

    # Fix RIFF size field
    if report.structure_broken:
        riff_size = struct.unpack("<I", data[4:8])[0]
        correct_size = len(data) - 8
        if riff_size != correct_size:
            struct.pack_into("<I", data, 4, correct_size)
            result.actions_taken.append(
                f"Fixed RIFF size: {riff_size} → {correct_size}")

    return data


# ══════════════════════════════════════════════════════════════
#  GIF Repair
# ══════════════════════════════════════════════════════════════

def _repair_gif(data: bytearray, report: DamageReport,
                result: RepairResult) -> bytearray:
    """Repair GIF file damage."""

    # Fix header
    if report.header_damaged:
        if data[:3] != b"GIF":
            result.actions_failed.append("GIF header unrecoverable")
            return data
        if data[3:6] not in (b"87a", b"89a"):
            data[3:6] = bytearray(b"89a")
            result.actions_taken.append("Fixed GIF version to 89a")

    # Append trailer if missing
    if report.footer_missing:
        if data[-1:] != b"\x3B":
            # Trim trailing nulls
            end = len(data)
            while end > 6 and data[end - 1] == 0x00:
                end -= 1
            data = data[:end]
            data.append(0x3B)
            result.actions_taken.append("Appended GIF trailer (0x3B)")

    return data


# ══════════════════════════════════════════════════════════════
#  MPEG-PS (MPG/MPEG/VOB) Repair — Advanced
# ══════════════════════════════════════════════════════════════

# MPEG start codes (all begin with 00 00 01)
_MPEG_PACK_START   = b"\x00\x00\x01\xBA"   # Pack header
_MPEG_SYS_HEADER   = b"\x00\x00\x01\xBB"   # System header
_MPEG_PROGRAM_END  = b"\x00\x00\x01\xB9"   # Program end code
_MPEG_SEQ_HEADER   = b"\x00\x00\x01\xB3"   # Sequence header
_MPEG_SEQ_END      = b"\x00\x00\x01\xB7"   # Sequence end code
_MPEG_GOP_START    = b"\x00\x00\x01\xB8"   # Group of Pictures
_MPEG_PIC_START    = b"\x00\x00\x01\x00"   # Picture start code
_MPEG_EXT_START    = b"\x00\x00\x01\xB5"   # Extension start code
_MPEG_USER_DATA    = b"\x00\x00\x01\xB2"   # User data start code
_MPEG_START_PREFIX = b"\x00\x00\x01"        # Universal start code prefix

# Valid MPEG start code range (after 00 00 01)
_MPEG_VALID_CODES = set(range(0x00, 0xBA)) | {
    0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,  # PS specific
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,  # Video
} | set(range(0xC0, 0xF0))  # PES streams (audio, video, etc.)


def _repair_mpeg_ps(data: bytearray, report: DamageReport,
                    result: RepairResult) -> bytearray:
    """Advanced repair for MPEG Program Stream (MPG/MPEG/VOB) files.

    Techniques applied:
      1. Header reconstruction — ensure valid pack/sequence header at start
      2. Null region excision — surgically remove zeroed-out blocks
      3. Start code re-synchronization — find and align to valid MPEG start codes
      4. PES packet validation — check/fix PES headers within packs
      5. GOP boundary recovery — locate and preserve GOP structures
      6. Program end code — append proper MPEG-PS end code
      7. Trailing garbage removal — trim non-MPEG data from the end
    """
    if len(data) < 12:
        result.actions_failed.append("MPEG file too small to repair")
        return data

    original_len = len(data)

    # ── Step 1: Header reconstruction ──
    data = _mpeg_fix_header(data, report, result)

    # ── Step 2: Null region excision (the main repair for TRIM'd SSDs) ──
    if report.has_null_regions and report.null_region_percent > 15:
        data = _mpeg_excise_null_regions(data, result)

    # ── Step 3: Start code re-synchronization ──
    data = _mpeg_resync_start_codes(data, result)

    # ── Step 4: Trim trailing garbage ──
    data = _mpeg_trim_trailing(data, result)

    # ── Step 5: Append program end code if missing ──
    if report.footer_missing or bytes(data[-4:]) != _MPEG_PROGRAM_END:
        data = _mpeg_append_end_code(data, result)

    if len(data) != original_len:
        saved = original_len - len(data)
        if saved > 0:
            result.actions_taken.append(
                f"Reduced file by {saved:,} bytes ({saved * 100 / original_len:.1f}%)")

    return data


def _mpeg_fix_header(data: bytearray, report: DamageReport,
                     result: RepairResult) -> bytearray:
    """Ensure the file starts with a valid MPEG-PS pack header or sequence header."""
    # Check if file already starts with a valid start code
    if len(data) >= 4:
        if data[:4] in (_MPEG_PACK_START, _MPEG_SEQ_HEADER):
            return data  # Header is fine

    # Try to find the first valid start code near the beginning
    search_limit = min(len(data), 64 * 1024)  # Search first 64 KB
    best_pos = -1
    best_code = None

    # Priority: pack header > sequence header > any valid start code
    pack_pos = bytes(data[:search_limit]).find(_MPEG_PACK_START)
    seq_pos = bytes(data[:search_limit]).find(_MPEG_SEQ_HEADER)

    if pack_pos >= 0 and pack_pos < search_limit:
        best_pos = pack_pos
        best_code = "pack header"
    elif seq_pos >= 0 and seq_pos < search_limit:
        best_pos = seq_pos
        best_code = "sequence header"
    else:
        # Search for any valid start code prefix
        pos = 0
        while pos < search_limit - 4:
            sc_pos = bytes(data[pos:search_limit]).find(_MPEG_START_PREFIX)
            if sc_pos == -1:
                break
            abs_pos = pos + sc_pos
            if abs_pos + 3 < len(data) and data[abs_pos + 3] in _MPEG_VALID_CODES:
                best_pos = abs_pos
                best_code = f"start code 0x{data[abs_pos + 3]:02X}"
                break
            pos = abs_pos + 1

    if best_pos > 0 and best_code:
        data = data[best_pos:]
        result.actions_taken.append(
            f"Aligned to {best_code} (trimmed {best_pos:,} leading bytes)")
    elif best_pos == -1 and report.header_damaged:
        # Last resort: construct a minimal MPEG-1 pack header
        # Pack header: 00 00 01 BA + SCR fields + mux rate
        # MPEG-1 pack header format (12 bytes):
        #   00 00 01 BA  [SCR 5 bytes]  [mux_rate 3 bytes]
        mpeg1_pack = bytearray(b"\x00\x00\x01\xBA")
        # SCR = 0, marker bits set:  0010 0000 0000 0001 ... pattern
        mpeg1_pack.extend(b"\x21\x00\x01\x00\x01")  # SCR=0 with MPEG-1 markers
        mpeg1_pack.extend(b"\x80\x01\xE1")           # mux_rate with markers
        data = mpeg1_pack + data
        result.actions_taken.append("Reconstructed MPEG-1 pack header")

    return data


def _mpeg_excise_null_regions(data: bytearray,
                               result: RepairResult) -> bytearray:
    """Surgically remove zeroed-out blocks while preserving valid MPEG data.

    This is the key technique for SSD/TRIM-damaged MPG files where large
    portions have been zeroed out by the drive firmware.

    Strategy:
      - Scan the file in blocks (2048 bytes = 1 DVD sector)
      - Classify each block as 'data' or 'null'
      - Keep only 'data' blocks
      - Re-synchronize at MPEG start code boundaries after excision
    """
    BLOCK_SIZE = 2048  # DVD sector size, natural MPEG-PS boundary
    NULL_THRESHOLD = 0.92  # Block is 'null' if >92% zeros

    good_chunks = []
    null_blocks_removed = 0
    total_blocks = 0
    null_bytes_removed = 0
    in_null_run = False
    null_run_start = 0

    pos = 0
    while pos < len(data):
        block = data[pos:pos + BLOCK_SIZE]
        block_len = len(block)
        total_blocks += 1

        # Calculate zero ratio for this block
        zero_count = sum(1 for b in block if b == 0)
        zero_ratio = zero_count / block_len if block_len > 0 else 1.0

        if zero_ratio >= NULL_THRESHOLD:
            # This block is mostly zeros (TRIM'd or wiped)
            if not in_null_run:
                in_null_run = True
                null_run_start = pos
            null_blocks_removed += 1
            null_bytes_removed += block_len
        else:
            # This block has real data
            if in_null_run:
                in_null_run = False
            good_chunks.append(bytes(block))

        pos += BLOCK_SIZE

    if null_blocks_removed == 0:
        return data  # Nothing to excise

    if null_blocks_removed >= total_blocks - 1:
        # Almost entirely null — can't recover anything meaningful
        result.actions_failed.append(
            f"File is {null_blocks_removed}/{total_blocks} null blocks — "
            "insufficient data for reconstruction")
        return data

    # Reassemble from good chunks
    reassembled = bytearray()
    for chunk in good_chunks:
        reassembled.extend(chunk)

    result.actions_taken.append(
        f"Excised {null_blocks_removed} null blocks "
        f"({null_bytes_removed:,} bytes, "
        f"{null_bytes_removed * 100 / len(data):.0f}% of file)")

    # Re-synchronize: make sure we start at a valid start code
    sync_pos = _mpeg_find_next_start_code(reassembled, 0)
    if sync_pos > 0:
        reassembled = reassembled[sync_pos:]
        result.actions_taken.append(
            f"Re-synced to start code at offset {sync_pos} after excision")

    return reassembled


def _mpeg_find_next_start_code(data: bytearray, start: int) -> int:
    """Find the next valid MPEG start code from position 'start'.

    Returns the offset of the 00 00 01 prefix, or -1 if not found.
    """
    pos = start
    data_bytes = bytes(data)
    limit = len(data) - 4

    while pos < limit:
        idx = data_bytes.find(_MPEG_START_PREFIX, pos)
        if idx == -1 or idx + 3 >= len(data):
            return -1
        code = data[idx + 3]
        if code in _MPEG_VALID_CODES:
            return idx
        pos = idx + 1

    return -1


def _mpeg_resync_start_codes(data: bytearray,
                              result: RepairResult) -> bytearray:
    """Scan for broken regions between valid start codes and clean them up.

    Walks the stream looking for sequences of invalid bytes between
    valid MPEG start codes. If a gap contains mostly garbage/null,
    it's removed to create a cleaner stream.
    """
    if len(data) < 8:
        return data

    # Find all valid start code positions
    start_code_positions = []
    pos = 0
    data_bytes = bytes(data)
    limit = len(data) - 4
    MAX_CODES = 50000  # Safety limit

    while pos < limit and len(start_code_positions) < MAX_CODES:
        idx = data_bytes.find(_MPEG_START_PREFIX, pos)
        if idx == -1:
            break
        if idx + 3 < len(data) and data[idx + 3] in _MPEG_VALID_CODES:
            start_code_positions.append(idx)
        pos = idx + 1

    if len(start_code_positions) < 2:
        return data

    # Check gaps between consecutive start codes for garbage
    # A valid MPEG stream has start codes at reasonable intervals (< 64KB typically)
    MAX_GAP = 2 * 1024 * 1024  # 2 MB max between start codes
    GARBAGE_THRESHOLD = 0.80   # 80% zeros = garbage
    cleaned_parts = []
    garbage_removed = 0
    prev_end = 0

    for i, sc_pos in enumerate(start_code_positions):
        if sc_pos < prev_end:
            continue

        # Determine the extent of this start-code's data
        if i + 1 < len(start_code_positions):
            next_sc = start_code_positions[i + 1]
        else:
            next_sc = len(data)

        # Check if there's a gap of garbage between prev_end and sc_pos
        if sc_pos > prev_end:
            gap = data[prev_end:sc_pos]
            gap_len = len(gap)
            if gap_len > 16:
                zero_ratio = sum(1 for b in gap if b == 0) / gap_len
                if zero_ratio >= GARBAGE_THRESHOLD and gap_len > 512:
                    # This gap is garbage — skip it
                    garbage_removed += gap_len
                else:
                    # Keep the gap (could be valid entropy-coded data)
                    cleaned_parts.append(bytes(gap))
            else:
                cleaned_parts.append(bytes(gap))

        # Keep data from this start code to the next
        segment = data[sc_pos:next_sc]
        cleaned_parts.append(bytes(segment))
        prev_end = next_sc

    # Don't forget trailing data after last start code
    if prev_end < len(data):
        tail = data[prev_end:]
        zero_ratio = sum(1 for b in tail if b == 0) / len(tail) if len(tail) > 0 else 1
        if zero_ratio < GARBAGE_THRESHOLD or len(tail) <= 512:
            cleaned_parts.append(bytes(tail))
        else:
            garbage_removed += len(tail)

    if garbage_removed > 1024:
        cleaned = bytearray()
        for part in cleaned_parts:
            cleaned.extend(part)
        result.actions_taken.append(
            f"Removed {garbage_removed:,} bytes of inter-stream garbage")
        return cleaned

    return data


def _mpeg_trim_trailing(data: bytearray,
                         result: RepairResult) -> bytearray:
    """Remove trailing null bytes and non-MPEG garbage from the end."""
    if len(data) < 16:
        return data

    # Find the last valid start code
    search_from = max(0, len(data) - 4 * 1024 * 1024)  # Search last 4 MB
    last_sc = -1
    pos = len(data) - 4
    data_bytes = bytes(data)

    # Search backwards for the last start code
    while pos > search_from:
        idx = data_bytes.rfind(_MPEG_START_PREFIX, search_from, pos + 3)
        if idx == -1:
            break
        if idx + 3 < len(data) and data[idx + 3] in _MPEG_VALID_CODES:
            last_sc = idx
            break
        pos = idx - 1

    if last_sc == -1:
        # No start codes found — just trim trailing nulls
        end = len(data)
        while end > 64 and data[end - 1] == 0x00:
            end -= 1
        if end < len(data) - 64:
            trimmed = len(data) - end
            data = data[:end]
            result.actions_taken.append(
                f"Trimmed {trimmed:,} trailing null bytes")
        return data

    # Determine end of last start code's payload
    code_byte = data[last_sc + 3]

    if code_byte == 0xB9:  # Program end code — already has proper ending
        # Trim anything after the end code
        end_pos = last_sc + 4
        if end_pos < len(data):
            trimmed = len(data) - end_pos
            if trimmed > 0:
                data = data[:end_pos]
                result.actions_taken.append(
                    f"Trimmed {trimmed:,} bytes after program end code")
        return data

    # For PES packets (0xBD-0xEF, 0xC0-0xDF audio, 0xE0-0xEF video),
    # read the PES length to find end of packet
    if code_byte >= 0xBC and last_sc + 6 <= len(data):
        pes_len = struct.unpack(">H", data[last_sc + 4:last_sc + 6])[0]
        if pes_len > 0:
            packet_end = last_sc + 6 + pes_len
            if packet_end < len(data):
                trailing = len(data) - packet_end
                # Check if trailing data is mostly null
                tail = data[packet_end:]
                zero_ratio = sum(1 for b in tail if b == 0) / len(tail)
                if zero_ratio > 0.8 and trailing > 512:
                    data = data[:packet_end]
                    result.actions_taken.append(
                        f"Trimmed {trailing:,} trailing bytes after last PES packet")
    else:
        # For other start codes, trim trailing nulls
        end = len(data)
        while end > last_sc + 8 and data[end - 1] == 0x00:
            end -= 1
        if len(data) - end > 256:
            trimmed = len(data) - end
            data = data[:end]
            result.actions_taken.append(
                f"Trimmed {trimmed:,} trailing null bytes")

    return data


def _mpeg_append_end_code(data: bytearray,
                          result: RepairResult) -> bytearray:
    """Append the MPEG Program End code (00 00 01 B9) if not present."""
    if len(data) >= 4 and bytes(data[-4:]) == _MPEG_PROGRAM_END:
        return data  # Already present

    # Trim any trailing nulls first
    end = len(data)
    while end > 8 and data[end - 1] == 0x00:
        end -= 1
    if end < len(data) - 4:
        data = data[:end]

    data.extend(_MPEG_PROGRAM_END)
    result.actions_taken.append("Appended MPEG program end code (00 00 01 B9)")
    return data


# ══════════════════════════════════════════════════════════════
#  SWF (Flash) Repair
# ══════════════════════════════════════════════════════════════

def _repair_swf(data: bytearray, report: DamageReport,
                result: RepairResult) -> bytearray:
    """Repair SWF (Flash) files."""
    if len(data) < 8:
        result.actions_failed.append("SWF file too small to repair")
        return data

    # Fix header signature
    if report.header_damaged:
        if data[:3] not in (b"FWS", b"CWS", b"ZWS"):
            # Try to find a valid SWF signature nearby
            for sig in (b"FWS", b"CWS", b"ZWS"):
                idx = bytes(data[:1024]).find(sig)
                if idx >= 0:
                    data = data[idx:]
                    result.actions_taken.append(
                        f"Aligned to SWF signature at offset {idx}")
                    break
            else:
                result.actions_failed.append(
                    "Cannot find SWF header signature")
                return data

    # Fix file length field (bytes 4-7, little-endian)
    if len(data) >= 8:
        declared_size = struct.unpack("<I", data[4:8])[0]
        if declared_size != len(data):
            struct.pack_into("<I", data, 4, len(data))
            result.actions_taken.append(
                f"Fixed SWF size field: {declared_size:,} → {len(data):,}")

    # Trim trailing null bytes
    if report.has_null_regions:
        end = len(data)
        while end > 8 and data[end - 1] == 0x00:
            end -= 1
        if len(data) - end > 256:
            trimmed = len(data) - end
            data = data[:end]
            # Update size field
            struct.pack_into("<I", data, 4, len(data))
            result.actions_taken.append(
                f"Trimmed {trimmed:,} trailing null bytes from SWF")

    return data


# ══════════════════════════════════════════════════════════════
#  Generic Repair
# ══════════════════════════════════════════════════════════════

def _repair_generic(data: bytearray, report: DamageReport,
                    result: RepairResult) -> bytearray:
    """Generic repair for formats without specific handlers."""

    # Trim trailing null bytes
    original_len = len(data)
    end = len(data)
    while end > 64 and data[end - 1] == 0x00:
        end -= 1

    if end < original_len - 64:
        data = data[:end]
        trimmed = original_len - end
        result.actions_taken.append(
            f"Trimmed {trimmed} trailing null bytes")

    if not result.actions_taken:
        result.actions_failed.append(
            "No specific repair strategy for this format")

    return data


# ══════════════════════════════════════════════════════════════
#  Integrity Verification (post-save)
# ══════════════════════════════════════════════════════════════

def verify_saved_file(file_path: str, expected_data: bytes,
                      extension: str) -> IntegrityCheck:
    """Verify a saved file is not corrupted.

    Performs:
      1. File existence and readability check
      2. Size comparison
      3. MD5 checksum verification (readback vs expected)
      4. Format-specific validation of saved file
    """
    check = IntegrityCheck()
    check.file_path = file_path
    check.expected_size = len(expected_data)
    check.expected_md5 = hashlib.md5(expected_data).hexdigest()

    # 1. File existence
    if not os.path.exists(file_path):
        check.issues.append("File does not exist after save")
        return check

    # 2. Readability
    try:
        with open(file_path, "rb") as f:
            saved_data = f.read()
        check.is_readable = True
    except (IOError, OSError) as e:
        check.issues.append(f"Cannot read saved file: {e}")
        return check

    # 3. Size check
    check.actual_size = len(saved_data)
    if check.actual_size != check.expected_size:
        check.issues.append(
            f"Size mismatch: expected {check.expected_size}, "
            f"got {check.actual_size}")

    # 4. MD5 verification
    check.actual_md5 = hashlib.md5(saved_data).hexdigest()
    if check.actual_md5 != check.expected_md5:
        check.issues.append(
            f"MD5 mismatch: expected {check.expected_md5[:12]}…, "
            f"got {check.actual_md5[:12]}…")

    # 5. Format validation
    from .smart_filter import validate_carved_file
    check.format_valid = validate_carved_file(extension, saved_data)
    if not check.format_valid:
        check.issues.append("Saved file fails format validation")

    # Final verdict
    check.passed = (
        check.is_readable
        and check.actual_md5 == check.expected_md5
        and check.actual_size == check.expected_size
    )

    return check


def verify_data_integrity(data: bytes, extension: str) -> IntegrityCheck:
    """Verify data integrity before writing to disk.

    Checks the data in memory to ensure it won't produce a corrupt file.
    """
    check = IntegrityCheck()
    check.expected_size = len(data)
    check.actual_size = len(data)
    check.expected_md5 = hashlib.md5(data).hexdigest()
    check.actual_md5 = check.expected_md5
    check.is_readable = True

    if not data or len(data) < 8:
        check.issues.append("Data is empty or too small")
        return check

    # Run damage analysis
    damage = analyze_damage(extension, data)

    if damage.damage_level in ("severe", "fatal"):
        check.issues.append(
            f"Data has {damage.damage_level} damage: "
            + damage.short_summary)
        check.format_valid = False
    elif damage.damage_level == "moderate":
        check.issues.append(
            f"Data has moderate damage: {damage.short_summary}")
        check.format_valid = True  # Still saveable
    else:
        check.format_valid = True

    # Validate format
    from .smart_filter import validate_carved_file
    if not validate_carved_file(extension, data):
        check.format_valid = False
        if "format validation" not in " ".join(check.issues).lower():
            check.issues.append("Data fails format validation")

    check.passed = check.format_valid and len(check.issues) == 0
    return check
