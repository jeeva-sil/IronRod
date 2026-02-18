"""
Parallel Scanning Engine — multiprocessing-based partition scanning.

PROFESSIONAL APPROACH
─────────────────────
❌ Python threads → GIL blocks true parallelism for CPU-bound work.
✅ multiprocessing → One process per partition/range = true parallelism.

Architecture:
  • Split scan ranges across N worker processes.
  • Each worker independently carves files from its assigned range.
  • Results are collected via a multiprocessing Queue.
  • A single coordinator process merges and deduplicates results.

This module handles ALL file signatures — images, videos, audio,
and documents — matching the full capability of the main scanner.
"""

import os
import time
import struct
import logging
import multiprocessing as mp
from multiprocessing import Queue, Process
from dataclasses import dataclass
from typing import Optional, Callable

from .signatures import (
    SignatureInfo,
    HEADER_SIGNATURES,
    RIFF_TYPES,
    FTYP_BRANDS,
    SIG_MKV,
    SIG_WEBM,
    SIG_TS,
    is_mpeg_ts,
)
from .smart_filter import (
    validate_carved_file,
    compute_md5,
    DeduplicationTracker,
    MIN_FILE_SIZE,
    calculate_entropy,
)

logger = logging.getLogger(__name__)


@dataclass
class WorkerResult:
    """Result from a single worker process."""
    worker_id: int
    range_start: int
    range_end: int
    files_found: int
    bytes_scanned: int
    elapsed: float
    # Serializable file records (can't pass RecoveredFile across processes)
    file_records: list  # list of dicts
    entropy_skipped: int = 0


@dataclass
class ParallelScanConfig:
    """Configuration for parallel scanning."""
    num_workers: int = 0            # 0 = auto-detect
    block_size: int = 4 * 1024 * 1024
    overlap: int = 64 * 1024
    skip_empty: bool = True
    min_range_per_worker: int = 50 * 1024 * 1024  # 50 MB minimum per worker
    max_workers: int = 8
    want_image: bool = True
    want_video: bool = True
    want_audio: bool = True
    want_document: bool = True
    want_archive: bool = True
    want_executable: bool = True
    want_font: bool = True
    want_database: bool = True
    want_system: bool = True


def optimal_worker_count(total_bytes: int, config: ParallelScanConfig) -> int:
    """
    Determine optimal number of worker processes.

    Rules:
      • At least 1 worker.
      • Each worker should scan at least min_range_per_worker bytes.
      • Never exceed physical CPU count (disk I/O is the bottleneck).
      • Cap at max_workers to avoid excessive process overhead.
    """
    if config.num_workers > 0:
        return min(config.num_workers, config.max_workers)

    cpu_count = os.cpu_count() or 2
    # Disk I/O is typically the bottleneck, not CPU.
    # More workers mostly helps for:
    #   - Multiple physical disks (rare in recovery)
    #   - Filesystem scanning with many small ranges
    # For raw sequential scan, 2-4 workers is usually optimal.
    max_by_size = max(1, total_bytes // config.min_range_per_worker)
    return min(max_by_size, cpu_count, config.max_workers)


def split_ranges_for_workers(
    ranges: list[tuple[int, int]],
    num_workers: int,
) -> list[list[tuple[int, int]]]:
    """
    Distribute scan ranges across workers as evenly as possible by total bytes.

    Each worker gets a list of (start, end) ranges to scan sequentially.
    """
    if num_workers <= 1 or not ranges:
        return [ranges]

    # Calculate total bytes per range
    range_sizes = [(end - start, start, end) for start, end in ranges]
    total_bytes = sum(s for s, _, _ in range_sizes)
    target_per_worker = total_bytes / num_workers

    worker_ranges: list[list[tuple[int, int]]] = [[] for _ in range(num_workers)]
    worker_bytes: list[int] = [0] * num_workers

    # Greedy assignment: give each range to the least-loaded worker
    for size, start, end in sorted(range_sizes, reverse=True):
        # Find worker with least bytes assigned
        min_worker = min(range(num_workers), key=lambda i: worker_bytes[i])
        worker_ranges[min_worker].append((start, end))
        worker_bytes[min_worker] += size

    # Remove empty worker assignments
    return [r for r in worker_ranges if r]


def split_sequential_for_workers(
    total_size: int,
    num_workers: int,
    overlap: int = 64 * 1024,
) -> list[tuple[int, int]]:
    """
    Split a sequential scan (brute-force mode) into ranges for parallel workers.

    Each range overlaps with the next by `overlap` bytes to catch signatures
    that straddle boundaries.
    """
    if num_workers <= 1:
        return [(0, total_size)]

    chunk_size = total_size // num_workers
    # Align to 4 KB boundaries for efficiency
    chunk_size = (chunk_size // 4096) * 4096
    if chunk_size < 1024 * 1024:  # Minimum 1 MB per worker
        return [(0, total_size)]

    ranges = []
    for i in range(num_workers):
        start = i * chunk_size
        if i == num_workers - 1:
            end = total_size
        else:
            end = (i + 1) * chunk_size + overlap  # Overlap into next range

        if start < total_size:
            ranges.append((start, min(end, total_size)))

    return ranges


def _worker_scan(
    worker_id: int,
    device_path: str,
    ranges: list[tuple[int, int]],
    config: ParallelScanConfig,
    output_dir: str,
    preview_only: bool,
    counter_start: int,
    result_queue: Queue,
    progress_queue: Queue,
    device_size: int = 0,
):
    """
    Worker process: scan assigned ranges and push results to queue.

    Runs in a separate process — no GIL contention.
    Handles ALL file signatures (images, videos, audio, documents).
    """
    try:
        from .mmap_reader import DiskReader, is_empty_block

        dedup = DeduplicationTracker()
        file_records = []
        bytes_scanned = 0
        entropy_skipped = 0
        counter = counter_start
        start_time = time.time()

        header_sigs = sorted(
            HEADER_SIGNATURES, key=lambda x: len(x[0]), reverse=True
        )

        # Category filter
        _want = {
            "Image": config.want_image,
            "Video": config.want_video,
            "Audio": config.want_audio,
            "Document": config.want_document,
            "Archive": config.want_archive,
            "Executable": config.want_executable,
            "Font": config.want_font,
            "Database": config.want_database,
            "System": config.want_system,
        }

        with open(device_path, "rb") as fd:
            # On macOS, seek(0,2) returns 0 for raw block devices
            # (/dev/rdisk*). Use the caller-provided device_size instead.
            fd_size = fd.seek(0, 2)
            fd.seek(0)
            if fd_size <= 0 and device_size > 0:
                fd_size = device_size
            elif fd_size <= 0 and ranges:
                # Last resort: derive from the ranges we were given
                fd_size = max(end for _, end in ranges)

            reader = DiskReader(fd, fd_size, use_mmap=True)

            for range_start, range_end in ranges:
                for offset, chunk in reader.iter_chunks(
                    start=range_start,
                    end=range_end,
                    block_size=config.block_size,
                    overlap=config.overlap,
                    skip_empty=config.skip_empty,
                ):
                    chunk_len = len(chunk)
                    bytes_scanned += chunk_len

                    # Skip empty blocks
                    if is_empty_block(chunk):
                        continue

                    # Entropy-adaptive filtering
                    if chunk_len >= 4096:
                        mid = chunk_len // 2
                        sample = chunk[:1365] + chunk[mid:mid+1365] + chunk[-1366:]
                        ent = calculate_entropy(sample)
                        if ent > _ENTROPY_RANDOM_THRESHOLD or ent < _ENTROPY_EMPTY_THRESHOLD:
                            entropy_skipped += 1
                            continue

                    # Search for ALL signatures
                    records = _search_chunk_worker_full(
                        fd, reader, chunk, offset, chunk_len, device_size,
                        _want, output_dir,
                        counter, preview_only, dedup, header_sigs,
                    )
                    for rec in records:
                        counter += 1
                        file_records.append(rec)

                    # Report progress periodically
                    if bytes_scanned % (20 * 1024 * 1024) < config.block_size:
                        progress_queue.put({
                            "worker_id": worker_id,
                            "bytes_scanned": bytes_scanned,
                            "files_found": len(file_records),
                        })

            reader.close()

        elapsed = time.time() - start_time
        result = WorkerResult(
            worker_id=worker_id,
            range_start=ranges[0][0] if ranges else 0,
            range_end=ranges[-1][1] if ranges else 0,
            files_found=len(file_records),
            bytes_scanned=bytes_scanned,
            elapsed=elapsed,
            file_records=file_records,
            entropy_skipped=entropy_skipped,
        )
        result_queue.put(result)

    except Exception as e:
        logger.error("Worker %d failed: %s", worker_id, e, exc_info=True)
        result_queue.put(WorkerResult(
            worker_id=worker_id,
            range_start=0, range_end=0,
            files_found=0, bytes_scanned=0,
            elapsed=0.0, file_records=[],
        ))


# ── Entropy thresholds (same as scanner.py) ──
_ENTROPY_RANDOM_THRESHOLD = 7.995
_ENTROPY_EMPTY_THRESHOLD = 0.5

# ── Ambiguous short headers that should NOT be used to trim maxread ──
_AMBIGUOUS_HEADERS = {
    b"BM", b"\x00\x00\x01\x00", b"\x00\x00\x01\xBA",
    b"\x00\x00\x01\xB3", b"II\x2A\x00", b"MM\x00\x2A",
    b"FWS", b"CWS",
    b"\xFF\xFB", b"\xFF\xFA", b"\xFF\xF3", b"\xFF\xF2",
}


def _find_all(data: bytes, pattern: bytes) -> list[int]:
    """Return all positions of pattern in data."""
    positions = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions


def _search_chunk_worker_full(
    fd, reader, chunk, offset, chunk_len, disk_size,
    want: dict, output_dir,
    counter, preview_only, dedup, header_sigs,
) -> list[dict]:
    """
    Search a chunk for ALL file signatures (worker-process version).

    Handles: fixed-header sigs, RIFF, ftyp (ISO BMFF), MPEG-TS, FORM/AIFF,
             ZIP/DOCX/XLSX/PPTX.
    Mirrors the main scanner's _search_chunk but returns serializable dicts.
    """
    found = []

    # ── Fixed-header signatures (all types) ──
    for header_bytes, sig in header_sigs:
        if not want.get(sig.category, True):
            continue

        for hit in _find_all(chunk, header_bytes):
            abs_off = offset + hit
            if dedup.is_duplicate_offset(abs_off):
                continue

            rec = _try_carve_by_mode(
                fd, reader, abs_off, disk_size, sig,
                output_dir, counter + len(found), preview_only,
            )
            if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                dedup.register(abs_off)
                rec.pop("_data", None)
                found.append(rec)

    # ── RIFF-based formats (WebP, AVI, WAV) ──
    for hit in _find_all(chunk, b"RIFF"):
        if hit + 12 > chunk_len:
            continue
        sub_type = bytes(chunk[hit + 8:hit + 12])
        sig = RIFF_TYPES.get(sub_type)
        if sig is None:
            continue
        if not want.get(sig.category, True):
            continue

        abs_off = offset + hit
        if dedup.is_duplicate_offset(abs_off):
            continue

        rec = _try_carve_riff(fd, reader, abs_off, disk_size, sig,
                              output_dir, counter + len(found), preview_only,
                              chunk, hit, chunk_len)
        if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
            dedup.register(abs_off)
            rec.pop("_data", None)
            found.append(rec)

    # ── MPEG-TS detection ──
    if want.get("Video", True):
        for hit in _find_all(chunk, b"\x47"):
            abs_off = offset + hit
            if abs_off % 188 != 0 and abs_off % 512 != 0:
                continue
            if dedup.is_duplicate_offset(abs_off):
                continue
            if hit + 188 * 4 <= chunk_len and is_mpeg_ts(chunk, hit):
                rec = _try_carve_maxread(
                    fd, reader, abs_off, disk_size, SIG_TS,
                    output_dir, counter + len(found), preview_only,
                )
                if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                    dedup.register(abs_off)
                    rec.pop("_data", None)
                    found.append(rec)

    # ── ISO Base Media (ftyp → MP4/MOV/HEIC/M4A/3GP) ──
    for hit in _find_all(chunk, b"ftyp"):
        box_start = hit - 4
        if box_start < 0:
            continue
        abs_off = offset + box_start
        if box_start + 12 > chunk_len:
            continue

        box_size = struct.unpack(">I", chunk[box_start:box_start + 4])[0]
        if box_size < 8 or box_size > 8192:
            continue

        brand_start = hit + 4
        if brand_start + 4 > chunk_len:
            continue
        brand = bytes(chunk[brand_start:brand_start + 4])

        sig = FTYP_BRANDS.get(brand) or FTYP_BRANDS.get(brand.lower())
        if sig is None:
            continue
        if not want.get(sig.category, True):
            continue
        if dedup.is_duplicate_offset(abs_off):
            continue

        rec = _try_carve_isobmff(
            fd, reader, abs_off, disk_size, sig,
            output_dir, counter + len(found), preview_only,
        )
        if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
            dedup.register(abs_off)
            rec.pop("_data", None)
            found.append(rec)

    # ── FORM-based AIFF ──
    if want.get("Audio", True):
        from .signatures import SIG_AIFF
        for hit in _find_all(chunk, b"FORM"):
            if hit + 12 > chunk_len:
                continue
            sub_type = bytes(chunk[hit + 8:hit + 12])
            if sub_type not in (b"AIFF", b"AIFC"):
                continue
            abs_off = offset + hit
            if dedup.is_duplicate_offset(abs_off):
                continue
            rec = _try_carve_riff(fd, reader, abs_off, disk_size, SIG_AIFF,
                                  output_dir, counter + len(found), preview_only,
                                  chunk, hit, chunk_len)
            if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                dedup.register(abs_off)
                rec.pop("_data", None)
                found.append(rec)

    # ── ZIP/DOCX/XLSX/PPTX/EPUB/ODT/ODS/ODP detection ──
    if want.get("Document", True) or want.get("Archive", True):
        from .signatures import (
            SIG_ZIP, SIG_DOCX, SIG_XLSX, SIG_PPTX,
            SIG_EPUB, SIG_ODT, SIG_ODS, SIG_ODP,
        )
        for hit in _find_all(chunk, b"PK\x03\x04"):
            abs_off = offset + hit
            if dedup.is_duplicate_offset(abs_off):
                continue
            sig = SIG_ZIP
            if hit + 34 < chunk_len:
                fn_len = struct.unpack("<H", chunk[hit + 26:hit + 28])[0]
                if fn_len > 0 and hit + 30 + fn_len <= chunk_len:
                    first_name = chunk[hit + 30:hit + 30 + fn_len]
                    try:
                        name_str = first_name.decode("utf-8", errors="replace")
                    except Exception:
                        name_str = ""
                    if name_str.startswith("word/"):
                        sig = SIG_DOCX
                    elif name_str.startswith("xl/"):
                        sig = SIG_XLSX
                    elif name_str.startswith("ppt/"):
                        sig = SIG_PPTX
                    elif name_str == "mimetype":
                        extra_len_off = hit + 28
                        if extra_len_off + 2 <= chunk_len:
                            extra_len = struct.unpack("<H", chunk[extra_len_off:extra_len_off + 2])[0]
                            data_off = hit + 30 + fn_len + extra_len
                            if data_off + 40 <= chunk_len:
                                mime_data = chunk[data_off:data_off + 60]
                                if b"application/epub+zip" in mime_data:
                                    sig = SIG_EPUB
                                elif b"opendocument.text" in mime_data:
                                    sig = SIG_ODT
                                elif b"opendocument.spreadsheet" in mime_data:
                                    sig = SIG_ODS
                                elif b"opendocument.presentation" in mime_data:
                                    sig = SIG_ODP
            if not want.get(sig.category, True):
                continue
            rec = _try_carve_maxread(
                fd, reader, abs_off, disk_size, sig,
                output_dir, counter + len(found), preview_only,
            )
            if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                dedup.register(abs_off)
                rec.pop("_data", None)
                found.append(rec)

    # ── TAR detection (ustar at offset 257) ──
    if want.get("Archive", True):
        from .signatures import SIG_TAR
        for hit in _find_all(chunk, b"ustar"):
            tar_start = hit - 257
            if tar_start < 0:
                continue
            abs_off = offset + tar_start
            if abs_off % 512 != 0:
                continue
            if dedup.is_duplicate_offset(abs_off):
                continue
            rec = _try_carve_maxread(
                fd, reader, abs_off, disk_size, SIG_TAR,
                output_dir, counter + len(found), preview_only,
            )
            if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                dedup.register(abs_off)
                rec.pop("_data", None)
                found.append(rec)

    # ── ISO 9660 detection (CD001 at offset 32769) ──
    if want.get("Archive", True):
        from .signatures import SIG_ISO
        for hit in _find_all(chunk, b"CD001"):
            iso_start = hit - 32769
            if iso_start < 0:
                continue
            abs_off = offset + iso_start
            if abs_off % 2048 != 0:
                continue
            if dedup.is_duplicate_offset(abs_off):
                continue
            rec = _try_carve_maxread(
                fd, reader, abs_off, disk_size, SIG_ISO,
                output_dir, counter + len(found), preview_only,
            )
            if rec and not dedup.is_duplicate_content(rec.get("_data", b"")):
                dedup.register(abs_off)
                rec.pop("_data", None)
                found.append(rec)

    return found


def _try_carve_by_mode(fd, reader, offset, disk_size, sig,
                       output_dir, counter, preview_only):
    """Dispatch carving by sig.carve_mode."""
    mode = sig.carve_mode
    if mode == "footer":
        return _try_carve_footer(fd, reader, offset, disk_size, sig,
                                 output_dir, counter, preview_only)
    elif mode == "isobmff":
        return _try_carve_isobmff(fd, reader, offset, disk_size, sig,
                                  output_dir, counter, preview_only)
    elif mode == "header":
        return _try_carve_header_size(fd, reader, offset, disk_size, sig,
                                      output_dir, counter, preview_only)
    else:
        return _try_carve_maxread(fd, reader, offset, disk_size, sig,
                                  output_dir, counter, preview_only)


def _try_carve_footer(fd, reader, offset, disk_size, sig, output_dir, counter, preview_only):
    """Carve a footer-based file (JPEG, PNG, PDF, etc.). Returns a dict record or None."""
    try:
        max_read = min(sig.max_size, disk_size - offset)
        if max_read < sig.min_size:
            return None

        data = reader.read_at(offset, min(max_read, 8 * 1024 * 1024))
        if not data or len(data) < sig.min_size:
            return None

        footer = sig.footer
        if footer:
            if sig.extension == "jpg":
                end_pos = data.rfind(footer)
            else:
                end_pos = data.find(footer)
            if end_pos != -1:
                data = data[:end_pos + len(footer)]

        if len(data) < sig.min_size:
            return None
        if not validate_carved_file(sig.extension, data):
            return None

        md5 = compute_md5(data)
        saved_path = ""
        if not preview_only and output_dir:
            saved_path = _save_file_worker(data, sig, counter, output_dir)

        return {
            "extension": sig.extension,
            "category": sig.category,
            "description": sig.description,
            "offset": offset,
            "size": len(data),
            "md5": md5,
            "saved_path": saved_path,
            "_data": data,
        }
    except Exception:
        return None


def _try_carve_header_size(fd, reader, offset, disk_size, sig,
                           output_dir, counter, preview_only):
    """Carve a file with size in header (BMP, ICO)."""
    try:
        hdr = reader.read_at(offset, 256)
        if not hdr or len(hdr) < 14:
            return None
        if not validate_carved_file(sig.extension, hdr):
            return None

        ext = sig.extension
        if ext == "bmp":
            file_size = struct.unpack("<I", hdr[2:6])[0]
        elif ext == "ico":
            if len(hdr) < 6:
                return None
            count = struct.unpack("<H", hdr[4:6])[0]
            if count == 0 or count > 256:
                return None
            dir_end = 6 + count * 16
            if dir_end > len(hdr):
                return None
            max_end = dir_end
            for i in range(count):
                eo = 6 + i * 16
                if eo + 16 > len(hdr):
                    break
                img_sz = struct.unpack("<I", hdr[eo + 8:eo + 12])[0]
                img_off = struct.unpack("<I", hdr[eo + 12:eo + 16])[0]
                end = img_off + img_sz
                if end > max_end:
                    max_end = end
            file_size = max_end
        else:
            return _try_carve_maxread(fd, reader, offset, disk_size, sig,
                                      output_dir, counter, preview_only)

        if file_size < sig.min_size or file_size > sig.max_size:
            return None
        if offset + file_size > disk_size:
            file_size = disk_size - offset

        data = reader.read_at(offset, file_size)
        if not data or len(data) < sig.min_size:
            return None
        if not validate_carved_file(sig.extension, data):
            return None

        md5 = compute_md5(data)
        saved_path = ""
        if not preview_only and output_dir:
            saved_path = _save_file_worker(data, sig, counter, output_dir)

        return {
            "extension": sig.extension,
            "category": sig.category,
            "description": sig.description,
            "offset": offset,
            "size": len(data),
            "md5": md5,
            "saved_path": saved_path,
            "_data": data,
        }
    except Exception:
        return None


def _try_carve_riff(fd, reader, offset, disk_size, sig,
                    output_dir, counter, preview_only,
                    chunk=b"", hit=0, chunk_len=0):
    """Carve a RIFF/FORM-based file (WebP, AVI, WAV, AIFF)."""
    try:
        if chunk and hit + 8 <= chunk_len:
            riff_data_size = struct.unpack("<I", chunk[hit + 4:hit + 8])[0]
        else:
            hdr = reader.read_at(offset, 12)
            if len(hdr) < 12:
                return None
            riff_data_size = struct.unpack("<I", hdr[4:8])[0]

        file_size = riff_data_size + 8
        if file_size < sig.min_size or file_size > sig.max_size:
            return None
        if offset + file_size > disk_size:
            file_size = disk_size - offset

        data = reader.read_at(offset, file_size)
        if not data or len(data) < sig.min_size:
            return None
        if not validate_carved_file(sig.extension, data):
            return None

        md5 = compute_md5(data)
        saved_path = ""
        if not preview_only and output_dir:
            saved_path = _save_file_worker(data, sig, counter, output_dir)

        return {
            "extension": sig.extension,
            "category": sig.category,
            "description": sig.description,
            "offset": offset,
            "size": len(data),
            "md5": md5,
            "saved_path": saved_path,
            "_data": data,
        }
    except Exception:
        return None


def _try_carve_maxread(fd, reader, offset, disk_size, sig,
                       output_dir, counter, preview_only):
    """Carve a file by reading up to max_size (for formats without exact size)."""
    try:
        max_read = min(sig.max_size, disk_size - offset)
        if max_read < sig.min_size:
            return None

        if sig.category == "Image":
            cap = min(max_read, 50 * 1024 * 1024)
        elif sig.category in ("Audio", "Document"):
            cap = min(max_read, 100 * 1024 * 1024)
        else:
            cap = min(max_read, 200 * 1024 * 1024)

        data = reader.read_at(offset, cap)
        if not data or len(data) < sig.min_size:
            return None

        # Find next header boundary to trim
        search_start = max(sig.min_size, 64 * 1024)
        if sig.category == "Audio":
            search_start = max(sig.min_size, 128 * 1024)
        trim_pos = _find_next_header_worker(data, search_start)
        if trim_pos is not None and trim_pos > sig.min_size:
            data = data[:trim_pos]

        if len(data) < sig.min_size:
            return None
        if not validate_carved_file(sig.extension, data):
            return None

        md5 = compute_md5(data)
        saved_path = ""
        if not preview_only and output_dir:
            saved_path = _save_file_worker(data, sig, counter, output_dir)

        return {
            "extension": sig.extension,
            "category": sig.category,
            "description": sig.description,
            "offset": offset,
            "size": len(data),
            "md5": md5,
            "saved_path": saved_path,
            "_data": data,
        }
    except Exception:
        return None


def _find_next_header_worker(data: bytes, start: int):
    """Find next file header boundary for trimming maxread carves."""
    best = None
    search_data = data[start:]
    for header_bytes, _sig in HEADER_SIGNATURES:
        if header_bytes in _AMBIGUOUS_HEADERS:
            continue
        pos = search_data.find(header_bytes)
        if pos != -1:
            actual_pos = start + pos
            if best is None or actual_pos < best:
                best = actual_pos

    # RIFF
    pos = search_data.find(b"RIFF")
    if pos != -1:
        sub_off = pos + 8
        if sub_off + 4 <= len(search_data):
            sub = search_data[sub_off:sub_off + 4]
            if sub in RIFF_TYPES:
                actual_pos = start + pos
                if best is None or actual_pos < best:
                    best = actual_pos

    # ftyp
    idx = 0
    while idx < len(search_data):
        pos = search_data.find(b"ftyp", idx)
        if pos == -1 or pos < 4:
            break
        box_start = pos - 4
        box_sz = struct.unpack(">I", search_data[box_start:box_start + 4])[0]
        if 8 <= box_sz <= 65536:
            brand_off = pos + 4
            if brand_off + 4 <= len(search_data):
                brand = search_data[brand_off:brand_off + 4]
                if brand in FTYP_BRANDS or brand.lower() in FTYP_BRANDS:
                    actual_pos = start + box_start
                    if best is None or actual_pos < best:
                        best = actual_pos
                    break
        idx = pos + 1

    return best


def _try_carve_isobmff(fd, reader, offset, disk_size, sig, output_dir, counter, preview_only):
    """Carve an ISO Base Media file by walking box structure. Returns a dict record or None."""
    KNOWN_BOXES = {
        b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
        b"pdin", b"moof", b"mfra", b"meta", b"styp", b"sidx",
        b"ssix", b"prft", b"uuid",
    }
    try:
        max_read = min(sig.max_size, disk_size - offset)
        if max_read < sig.min_size:
            return None

        # Walk boxes
        pos = 0
        box_count = 0
        while pos < max_read:
            header = reader.read_at(offset + pos, 8)
            if len(header) < 8:
                break
            box_size = struct.unpack(">I", header[:4])[0]
            box_type = header[4:8]
            if box_size == 1:
                ext = reader.read_at(offset + pos + 8, 8)
                if len(ext) < 8:
                    break
                box_size = struct.unpack(">Q", ext)[0]
                if box_size < 16:
                    break
            elif box_size == 0:
                if box_count >= 2:
                    break
                remaining = min(max_read - pos, 500 * 1024 * 1024)
                pos += remaining
                break
            if box_size < 8:
                break
            if box_type not in KNOWN_BOXES:
                if box_count >= 2:
                    break
                break
            box_count += 1
            pos += box_size
            if pos > max_read:
                pos = max_read
                break

        file_size = pos
        if box_count < 2 or file_size < sig.min_size:
            return None

        data = reader.read_at(offset, file_size)
        if len(data) < sig.min_size:
            return None
        if not validate_carved_file(sig.extension, data):
            return None

        md5 = compute_md5(data)
        saved_path = ""
        if not preview_only and output_dir:
            saved_path = _save_file_worker(data, sig, counter, output_dir)

        return {
            "extension": sig.extension,
            "category": sig.category,
            "description": sig.description,
            "offset": offset,
            "size": len(data),
            "md5": md5,
            "saved_path": saved_path,
            "_data": data,
        }
    except Exception:
        return None


def _save_file_worker(data, sig, counter, output_dir):
    """Save a carved file (worker process version)."""
    subdir = os.path.join(output_dir, sig.category)
    os.makedirs(subdir, exist_ok=True)
    filename = f"recovered_{counter + 1:06d}.{sig.extension}"
    path = os.path.join(subdir, filename)
    if os.path.exists(path):
        base, ext = os.path.splitext(path)
        i = 1
        while os.path.exists(path):
            path = f"{base}_{i}{ext}"
            i += 1
    with open(path, "wb") as f:
        f.write(data)
    return path
