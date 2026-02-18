"""
Disk Scanner Engine — Raw binary file carving for deleted photo/video recovery.

SCANNING MODES
──────────────
1. FORENSIC MODE (exFAT / FAT32)
   • Parses the filesystem's allocation bitmap to identify free clusters.
   • Scans ONLY unallocated disk space — skips existing files entirely.
   • Much faster on large drives (e.g. 931 GB drive with 40% free → scans 372 GB).
   • Eliminates false positives from existing (non-deleted) files.
   • Requires: sudo access + supported filesystem (exFAT or FAT32).

2. BRUTE-FORCE MODE (fallback)
   • Scans every byte of the device sequentially.
   • Used when filesystem is APFS, NTFS, or unrecognized.
   • Slower and may find existing files as false positives.

HOW FILE CARVING WORKS
──────────────────────
1.  Open the raw block device in read-only binary mode.
2.  Read large chunks (4 MB) into memory.
3.  Within each chunk, search for EVERY occurrence of known magic bytes
    using Python's fast bytes.find().
4.  For JPEG and PNG: search for the end-of-file footer marker.
5.  For ISO Base Media (MP4, MOV, HEIC): detect by "ftyp" at offset +4,
    then walk the box/atom structure to compute total file size.
6.  Validate, de-duplicate, and save.
"""

import os
import re
import sys
import time
import json
import struct
import hashlib
import logging
import platform
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Callable

from .signatures import (
    SignatureInfo,
    HEADER_SIGNATURES,
    RIFF_TYPES,
    FTYP_BRANDS,
    ALL_SIGNATURES,
    get_all_categories,
    is_mpeg_ts,
    SIG_MKV,
    SIG_WEBM,
    SIG_TS,
)
from .smart_filter import (
    validate_carved_file,
    compute_md5,
    DeduplicationTracker,
    MIN_FILE_SIZE,
    calculate_entropy,
)
from .filesystem import detect_and_parse, FilesystemInfo
from .trim_detect import detect_drive_health, DriveHealthInfo
from .mmap_reader import DiskReader, is_empty_block, align_down
from .tsk_scanner import (
    scan_deleted_files as tsk_scan_deleted,
    TSKDeletedFile,
    save_tsk_file,
    is_available as tsk_is_available,
)
from .damage_detector import DamageReport, analyze_damage
from .file_repair import RepairResult, IntegrityCheck

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
#  Data Classes
# ─────────────────────────────────────────────────────────────

@dataclass
class RecoveredFile:
    """A file carved from raw disk sectors or found via TSK filesystem analysis."""
    signature: SignatureInfo
    offset: int                     # Byte offset on the raw device
    size: int                       # Carved file size
    md5: str = ""
    recovered_path: str = ""        # Where we saved it (empty in preview mode)
    raw_device_path: str = ""       # Raw device for deferred saves
    timestamp: float = 0.0
    is_valid: bool = True
    is_saved: bool = False
    original_name: str = ""         # Original filename (TSK recovery only)
    original_path: str = ""         # Original path on disk (TSK recovery only)
    source: str = "carved"          # "carved" or "tsk" (filesystem-level)
    tsk_inode: int = 0              # Inode/MFT entry (TSK only)
    # Damage detection & repair
    damage_report: object = None    # DamageReport (set during scan/save)
    repair_result: object = None    # RepairResult (set after repair attempt)
    integrity_check: object = None  # IntegrityCheck (set after save)
    is_repaired: bool = False       # Was this file repaired?
    # Deep workability validation
    is_truly_workable: bool = False   # Passed deep decode validation?
    workability_reason: str = ""      # Why workable or not
    is_validated: bool = False        # Has deep validation been run?

    @property
    def damage_level(self) -> str:
        if self.damage_report and hasattr(self.damage_report, 'damage_level'):
            return self.damage_report.damage_level
        return "unknown"

    @property
    def damage_icon(self) -> str:
        if self.damage_report and hasattr(self.damage_report, 'status_icon'):
            return self.damage_report.status_icon
        return "❓"

    @property
    def is_repairable(self) -> bool:
        if self.damage_report and hasattr(self.damage_report, 'repairable'):
            return self.damage_report.repairable
        return False

    @property
    def category(self) -> str:
        return self.signature.category

    @property
    def extension(self) -> str:
        return self.signature.extension

    @property
    def description(self) -> str:
        if self.source == "tsk" and self.original_name:
            return f"[TSK] {self.signature.description}"
        return self.signature.description

    @property
    def display_name(self) -> str:
        if self.original_name:
            return self.original_name
        return f"recovered_{self.offset:012X}.{self.extension}"

    @property
    def size_human(self) -> str:
        return _human_size(self.size)

    @property
    def sector(self) -> int:
        return self.offset // 512


@dataclass
class ScanProgress:
    total_bytes: int = 0
    scanned_bytes: int = 0
    files_found: int = 0
    current_offset: int = 0
    elapsed_time: float = 0.0
    is_scanning: bool = False
    is_cancelled: bool = False
    status_message: str = "Ready"
    # Forensic mode info
    scan_mode: str = "brute-force"   # "forensic" or "brute-force"
    fs_type: str = ""                # e.g. "exfat", "fat32", "ntfs"
    total_clusters: int = 0
    free_clusters: int = 0
    free_bytes: int = 0              # Actual unallocated bytes to scan
    free_ranges_count: int = 0       # Number of contiguous free ranges
    # Drive health / TRIM info
    drive_type: str = ""             # "SSD", "HDD", "NVMe SSD", etc.
    trim_enabled: bool = False
    trim_warning: str = ""
    recovery_confidence: str = ""    # "high", "medium", "low", "none"
    # Performance stats
    skipped_empty_bytes: int = 0     # Bytes skipped (all-zero blocks)
    using_mmap: bool = False

    @property
    def progress_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return min(100.0, (self.scanned_bytes / self.total_bytes) * 100)

    @property
    def speed_mbps(self) -> float:
        if self.elapsed_time <= 0:
            return 0.0
        return (self.scanned_bytes / (1024 * 1024)) / self.elapsed_time

    @property
    def eta_seconds(self) -> float:
        speed = self.speed_mbps
        if speed <= 0:
            return 0.0
        remaining_mb = (self.total_bytes - self.scanned_bytes) / (1024 * 1024)
        return remaining_mb / speed


@dataclass
class DriveInfo:
    device_path: str
    mount_point: str
    label: str
    filesystem: str
    total_size: int
    free_size: int = 0
    is_removable: bool = False
    drive_type: str = ""      # SSD, HDD, USB, SD Card, NVMe, Optical, Disk Image, Unknown
    is_mounted: bool = True
    bus_protocol: str = ""    # USB, SATA, NVMe, Thunderbolt, PCIe, etc.

    @property
    def size_human(self) -> str:
        return _human_size(self.total_size)

    @property
    def free_human(self) -> str:
        return _human_size(self.free_size)

    @property
    def type_icon(self) -> str:
        icons = {
            "SSD": "⚡", "NVMe": "⚡", "NVMe SSD": "⚡",
            "PCIe SSD": "⚡", "PCIe": "⚡",
            "External SSD (USB)": "⚡", "External SSD (TB)": "⚡",
            "External SSD (Thunderbolt)": "⚡",
            "External SSD (FireWire)": "⚡",
            "HDD": "💾", "USB": "🔌", "USB Drive": "🔌",
            "SD Card": "💳", "CF Card": "💳", "Memory Card": "💳",
            "Optical": "💿", "CD/DVD": "💿",
            "Disk Image": "📀", "Virtual": "🖥️",
            "eMMC": "📱", "Internal": "💻",
        }
        return icons.get(self.drive_type, "💽")

    @property
    def display_name(self) -> str:
        lbl = self.label or self.mount_point or "Unnamed"
        icon = self.type_icon
        mount = f" ({self.mount_point})" if self.mount_point else " (unmounted)"
        dtype = f" [{self.drive_type}]" if self.drive_type else ""
        return f"{icon} {lbl}{mount} — {self.size_human} [{self.filesystem}]{dtype}"


# ─────────────────────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────────────────────

class DiskScanner:
    """
    Raw binary file carving scanner.

    Reads a block device (or disk image) byte-by-byte and carves
    deleted photos/videos by matching file signatures.
    """

    READ_CHUNK = 4 * 1024 * 1024       # Read 4 MB at a time
    OVERLAP = 64 * 1024                 # 64 KB overlap between chunks (catch headers at boundary)
    FOOTER_SEARCH_LIMIT = 50 * 1024 * 1024  # Search up to 50 MB for footer

    def __init__(self):
        self.progress = ScanProgress()
        self._on_progress: Optional[Callable] = None
        self._on_file_found: Optional[Callable] = None
        self._dedup = DeduplicationTracker()
        self._recovery_log: list[dict] = []
        self._drive_health: Optional[DriveHealthInfo] = None
        self._reader: Optional[DiskReader] = None
        self._skip_trim_check: bool = False
        self._ssd_mode: bool = False           # SSD-aware scanning mode
        self._ssd_aggressive: bool = False     # Skip entropy filter for SSD

        # Pre-sort header sigs by length (longest first for priority)
        self._header_sigs = sorted(
            HEADER_SIGNATURES, key=lambda x: len(x[0]), reverse=True
        )
        self._max_header_len = max(len(h) for h, _ in HEADER_SIGNATURES)

        # ── Advanced scanning state ──
        self._entropy_skip_count = 0     # Blocks skipped by entropy filter
        self._entropy_scan_count = 0     # Blocks actually scanned
        self._fragment_candidates: list[dict] = []  # Unmatched headers for reassembly
        self._checkpoint_file: Optional[str] = None
        self._checkpoint_interval = 100 * 1024 * 1024  # Save checkpoint every 100 MB
        self._last_checkpoint_bytes = 0

    # ── Entropy-adaptive block classification ────────────────

    # Random/encrypted data has entropy ~7.99-8.0.
    # Compressed media (JPEG, MP4, etc.) has entropy ~6.0-7.98.
    # Structured data (headers, metadata) has entropy ~3.0-6.0.
    # Sparse/empty data has entropy ~0.0-1.0.
    ENTROPY_RANDOM_THRESHOLD = 7.995   # Above this → likely random/encrypted/TRIM'd
    ENTROPY_EMPTY_THRESHOLD = 0.5      # Below this → likely zeroed/uninitialized

    def _classify_block_entropy(self, data: bytes) -> str:
        """Classify a block by its entropy profile.

        Returns:
            'skip'   — block is random/encrypted/TRIM'd, no recoverable data
            'empty'  — block is near-zero, skip
            'scan'   — block may contain recoverable file data
        """
        # Sample 4096 bytes from the start, middle, and end for speed
        sample_size = min(4096, len(data))
        if len(data) <= sample_size:
            sample = data
        else:
            third = sample_size // 3
            sample = data[:third] + data[len(data)//2:len(data)//2+third] + data[-third:]

        ent = calculate_entropy(sample)

        if ent > self.ENTROPY_RANDOM_THRESHOLD:
            return "skip"
        if ent < self.ENTROPY_EMPTY_THRESHOLD:
            return "empty"
        return "scan"

    def set_progress_callback(self, cb):
        self._on_progress = cb

    def set_file_found_callback(self, cb):
        self._on_file_found = cb

    def cancel(self):
        self.progress.is_cancelled = True

    def set_skip_trim_check(self, skip: bool):
        self._skip_trim_check = skip

    def set_ssd_mode(self, enabled: bool, aggressive: bool = False):
        """Enable SSD-aware scanning.

        Args:
            enabled: Use SSD-optimized scan strategy.
            aggressive: If True, disable entropy-based block skipping entirely
                        (slower but catches data in partially TRIM'd blocks).
        """
        self._ssd_mode = enabled
        self._ssd_aggressive = aggressive
        if aggressive:
            # For SSD with TRIM, raise the threshold so fewer blocks are
            # skipped — some partially TRIM'd blocks still hold data.
            self.ENTROPY_RANDOM_THRESHOLD = 7.999
        elif enabled:
            # Slightly more lenient for SSD without full TRIM
            self.ENTROPY_RANDOM_THRESHOLD = 7.998

    # ── Checkpoint / Resume ──────────────────────────────────

    def set_checkpoint_dir(self, checkpoint_dir: str):
        """Set directory for checkpoint files. Enables auto-save/resume."""
        os.makedirs(checkpoint_dir, exist_ok=True)
        self._checkpoint_file = os.path.join(checkpoint_dir, "scan_checkpoint.json")

    def _save_checkpoint(
        self, offset: int, file_counter: int,
        recovered_offsets: list[int], scan_mode: str,
        device_path: str,
    ):
        """Save scan state to checkpoint file for resume capability."""
        if not self._checkpoint_file:
            return
        try:
            checkpoint = {
                "version": 2,
                "timestamp": time.time(),
                "device_path": device_path,
                "scan_mode": scan_mode,
                "last_offset": offset,
                "file_counter": file_counter,
                "files_found": self.progress.files_found,
                "bytes_scanned": self.progress.scanned_bytes,
                "recovered_offsets": recovered_offsets[-500:],  # Last 500 for dedup
                "entropy_skipped": self._entropy_skip_count,
            }
            tmp = self._checkpoint_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(checkpoint, f)
            os.replace(tmp, self._checkpoint_file)
        except Exception as e:
            logger.debug("Checkpoint save failed: %s", e)

    def load_checkpoint(self, device_path: str) -> Optional[dict]:
        """Load checkpoint for a device. Returns checkpoint dict or None."""
        if not self._checkpoint_file or not os.path.exists(self._checkpoint_file):
            return None
        try:
            with open(self._checkpoint_file) as f:
                cp = json.load(f)
            if cp.get("device_path") != device_path:
                return None
            if cp.get("version", 0) < 2:
                return None
            # Checkpoint must be less than 24 hours old
            if time.time() - cp.get("timestamp", 0) > 86400:
                return None
            return cp
        except Exception:
            return None

    def clear_checkpoint(self):
        """Remove checkpoint file after successful scan completion."""
        if self._checkpoint_file and os.path.exists(self._checkpoint_file):
            try:
                os.remove(self._checkpoint_file)
            except Exception:
                pass

    @property
    def drive_health(self) -> Optional[DriveHealthInfo]:
        return self._drive_health

    def get_recovery_log(self) -> list[dict]:
        return list(self._recovery_log)

    # ─── TSK filesystem-level recovery ───────────────────────

    def _run_tsk_scan(
        self,
        raw_path: str,
        want_image: bool,
        want_video: bool,
        categories: Optional[set[str]],
        preview_only: bool,
    ) -> list[RecoveredFile]:
        """Run The Sleuth Kit scan to find deleted files via filesystem metadata.

        After TSK finds deleted directory entries, we **validate each file's
        actual data** by reading the first bytes from the device.  Files whose
        data doesn't match the expected format are included as damaged files
        so the repair engine can attempt recovery.
        """
        from .smart_filter import validate_file_data_matches_extension

        results: list[RecoveredFile] = []

        def on_status(msg: str):
            self.progress.status_message = msg
            self._notify_progress()

        try:
            on_status("🔍 TSK: Scanning filesystem for deleted files...")
            tsk_files = tsk_scan_deleted(
                raw_path,
                want_image=want_image,
                want_video=want_video,
                on_status=on_status,
                categories=categories,
            )

            if not tsk_files:
                return results

            on_status(f"🔍 TSK: Validating {len(tsk_files)} deleted files (checking data integrity)...")
            damaged_count = 0

            for tf in tsk_files:
                # Map extension to a SignatureInfo
                sig = self._ext_to_sig(tf.extension, tf.category)
                if sig is None:
                    continue

                is_data_damaged = False
                damage_report = None

                # ── Validate that the actual on-disk data matches ──
                if tf.offset > 0 and tf.size > 0:
                    try:
                        header = self._read_raw_header(raw_path, tf.offset, 4096)
                        if header and not validate_file_data_matches_extension(
                            tf.extension, header
                        ):
                            is_data_damaged = True
                            damaged_count += 1
                            logger.info(
                                "TSK: %s — data damaged/overwritten "
                                "(expected .%s, got %s) — marking for repair",
                                tf.name, tf.extension, header[:8].hex(),
                            )
                            # Run damage analysis on what we can read
                            read_size = min(tf.size, 1024 * 1024)
                            full_data = self._read_raw_header(
                                raw_path, tf.offset, read_size)
                            if full_data:
                                damage_report = analyze_damage(
                                    tf.extension, full_data,
                                    expected_size=tf.size)
                    except Exception:
                        pass  # If we can't read, still include it

                rf = RecoveredFile(
                    signature=sig,
                    offset=tf.offset,
                    size=tf.size,
                    md5="",
                    recovered_path="",
                    raw_device_path=tf.raw_device,
                    timestamp=tf.deleted_time or time.time(),
                    is_valid=not is_data_damaged,
                    is_saved=False,
                    original_name=tf.name,
                    original_path=tf.path,
                    source="tsk",
                    tsk_inode=tf.inode,
                )

                # Attach damage report
                if is_data_damaged:
                    if damage_report is None:
                        damage_report = DamageReport(
                            is_damaged=True,
                            damage_level="severe",
                            damage_score=0.6,
                            issues=["File data overwritten — header does not match expected format"],
                            header_damaged=True,
                            repairable=True,
                            repair_actions=[f"reconstruct_{tf.extension}_header"],
                        )
                    rf.damage_report = damage_report

                results.append(rf)

            if damaged_count:
                on_status(
                    f"🔍 TSK: {len(results)} files found "
                    f"({damaged_count} damaged — will attempt repair during save)"
                )
            elif results:
                on_status(f"✅ TSK: {len(results)} deleted files validated")

        except Exception as e:
            logger.warning("TSK scan failed: %s", e)
            on_status(f"⚠️ TSK scan encountered an error: {e}")

        return results

    @staticmethod
    def _read_raw_header(device: str, offset: int, size: int) -> bytes:
        """Read a small header from the raw device with sector alignment."""
        SECTOR = 512
        aligned_offset = (offset // SECTOR) * SECTOR
        padding = offset - aligned_offset
        aligned_size = size + padding
        if aligned_size % SECTOR != 0:
            aligned_size += SECTOR - (aligned_size % SECTOR)
        with open(device, "rb") as dev:
            dev.seek(aligned_offset)
            raw = dev.read(aligned_size)
        if not raw:
            return b""
        return raw[padding:padding + size]

    def _ext_to_sig(self, ext: str, category: str) -> Optional[SignatureInfo]:
        """Map a file extension to the best matching SignatureInfo."""
        ext = ext.lower()
        # Try exact match from ALL_SIGNATURES
        for sig in ALL_SIGNATURES:
            if sig.extension == ext and sig.category == category:
                return sig
        # Try common aliases
        _ALIASES = {
            "jpeg": "jpg", "mpeg": "mpg", "tif": "tiff",
            "mts": "ts", "m2ts": "ts", "asf": "wmv",
            "rmvb": "rm", "ogg": "ogv",
        }
        canon = _ALIASES.get(ext, ext)
        for sig in ALL_SIGNATURES:
            if sig.extension == canon:
                return sig
        # Fallback: create a generic SignatureInfo
        return SignatureInfo(
            category=category,
            extension=ext,
            description=f"{ext.upper()} ({category})",
            max_size=2 * 1024 * 1024 * 1024,
            min_size=1024,
            carve_mode="maxread",
        )

    # ─── Main entry point ────────────────────────────────────

    def scan(
        self,
        device_path: str,
        output_dir: str,
        categories: Optional[set[str]] = None,
        preview_only: bool = False,
    ) -> list[RecoveredFile]:
        """
        Scan a raw device or disk image for deleted photos/videos.

        Args:
            device_path:  Mount point, device path, or disk image file.
            output_dir:   Where to save recovered files (ignored in preview mode).
            categories:   Set of categories to recover (None = all).
            preview_only: Detect without saving files.
        """
        # Resolve to raw device path
        raw_path = self._resolve_raw_device(device_path)
        if not raw_path:
            self.progress.status_message = (
                "❌ Cannot access device. Run with sudo / Administrator."
            )
            self._notify_progress()
            return []

        # ── STEP 1: SSD + TRIM detection (critical pre-check) ──
        if not self._skip_trim_check and not os.path.isfile(raw_path):
            self.progress.status_message = "🔍 Detecting drive type (SSD/HDD) and TRIM status..."
            self._notify_progress()
            try:
                self._drive_health = detect_drive_health(device_path)
                dh = self._drive_health
                self.progress.drive_type = dh.drive_type
                self.progress.trim_enabled = dh.trim_enabled
                self.progress.trim_warning = dh.recovery_warning
                self.progress.recovery_confidence = dh.recovery_confidence
                logger.info("Drive health: %s", dh.summary)

                if dh.is_ssd_with_trim:
                    self.progress.status_message = (
                        "🛑 SSD + TRIM detected — recovery is almost impossible.\n"
                        f"Drive: {dh.model or dh.drive_type}\n"
                        "TRIM erases blocks at hardware level. Continuing scan anyway..."
                    )
                    self._notify_progress()
                    # We warn but don't abort — let the user decide

            except Exception as e:
                logger.warning("Drive health detection failed: %s", e)
                self._drive_health = None

        # Get device size
        total_size = self._get_device_size(raw_path)
        if total_size == 0:
            self.progress.status_message = "❌ Cannot determine device size."
            self._notify_progress()
            return []

        # Filter categories
        want_image = categories is None or "Image" in categories
        want_video = categories is None or "Video" in categories
        want_audio = categories is None or "Audio" in categories
        want_document = categories is None or "Document" in categories
        want_archive = categories is None or "Archive" in categories
        want_executable = categories is None or "Executable" in categories
        want_font = categories is None or "Font" in categories
        want_database = categories is None or "Database" in categories
        want_system = categories is None or "System" in categories

        # Prepare output
        if output_dir and not preview_only:
            os.makedirs(output_dir, exist_ok=True)

        # ── STEP 2: Forensic mode — parse filesystem allocation bitmap ──
        fs_info: Optional[FilesystemInfo] = None
        scan_ranges: Optional[list[tuple[int, int]]] = None

        try:
            self.progress.status_message = "🔬 Analyzing filesystem allocation bitmap..."
            self._notify_progress()
            fs_info = detect_and_parse(raw_path)
        except Exception as e:
            logger.warning("Filesystem detection failed: %s", e)

        if fs_info and fs_info.free_ranges:
            scan_mode = "forensic"
            scan_ranges = fs_info.free_ranges
            scan_total = fs_info.total_free_bytes
            logger.info(
                "FORENSIC MODE: %s filesystem, scanning %d free ranges "
                "(%s free out of %d clusters)",
                fs_info.fs_type.upper(), len(scan_ranges),
                fs_info.free_human, fs_info.total_clusters,
            )
        else:
            scan_mode = "brute-force"
            scan_total = total_size
            if fs_info:
                logger.info("Filesystem detected (%s) but no free ranges — falling back to brute-force", fs_info.fs_type)
            else:
                logger.info("No supported filesystem detected — using brute-force scan")

        # Init progress
        self.progress = ScanProgress(
            total_bytes=scan_total,
            is_scanning=True,
            scan_mode=scan_mode,
            fs_type=fs_info.fs_type if fs_info else "",
            total_clusters=fs_info.total_clusters if fs_info else 0,
            free_clusters=fs_info.free_clusters if fs_info else 0,
            free_bytes=fs_info.total_free_bytes if fs_info else 0,
            free_ranges_count=len(scan_ranges) if scan_ranges else 0,
            status_message=(
                f"🔬 Forensic scan: {fs_info.fs_type.upper()} — "
                f"scanning {fs_info.free_human} unallocated space "
                f"({fs_info.free_percent:.1f}% of disk, "
                f"{len(scan_ranges)} ranges)..."
                if scan_mode == "forensic" and fs_info
                else f"⚡ Brute-force scan of {_human_size(total_size)}..."
            ),
        )
        self._dedup.clear()
        self._recovery_log.clear()
        self._notify_progress()

        # ── STEP 2b: TSK filesystem-level deleted file recovery ──
        recovered: list[RecoveredFile] = []
        file_counter = 0
        start_time = time.time()
        total_skipped = 0

        if tsk_is_available() and not os.path.isfile(raw_path):
            tsk_results = self._run_tsk_scan(
                raw_path, want_image, want_video,
                categories, preview_only,
            )
            for rf in tsk_results:
                recovered.append(rf)
                file_counter += 1
                self.progress.files_found = len(recovered)
                self._dedup.register(rf.offset)
                if self._on_file_found:
                    self._on_file_found(rf)
            if tsk_results:
                logger.info("TSK pass found %d deleted files", len(tsk_results))

        # ── STEP 3: Raw binary carving scan ──

        try:
            with open(raw_path, "rb") as disk:
                # ── Initialize high-performance mmap reader ──
                self._reader = DiskReader(disk, total_size, use_mmap=True)
                self.progress.using_mmap = self._reader.is_mmap
                if self._reader.is_mmap:
                    logger.info("Using mmap for high-performance reads")
                else:
                    logger.info("Using buffered reads (mmap unavailable)")

                if scan_mode == "forensic" and scan_ranges:
                    # Try parallel scanning for large forensic scans
                    parallel_result = None
                    if scan_total >= self._PARALLEL_THRESHOLD:
                        try:
                            # Close reader — workers open their own
                            if self._reader:
                                self._reader.close()
                                self._reader = None
                            parallel_result = self._scan_parallel(
                                raw_path, scan_ranges, scan_total, total_size,
                                want_image, want_video, want_audio, want_document,
                                output_dir, file_counter, preview_only, start_time,
                                want_archive=want_archive,
                                want_executable=want_executable,
                                want_font=want_font,
                                want_database=want_database,
                                want_system=want_system,
                            )
                        except Exception as e:
                            logger.warning(
                                "Parallel scan failed, falling back: %s", e
                            )
                            parallel_result = None
                            # Re-open reader for fallback
                            self._reader = DiskReader(disk, total_size, use_mmap=True)

                    if parallel_result is not None:
                        recovered, file_counter = parallel_result
                    else:
                        # Re-initialize reader if closed for parallel attempt
                        if self._reader is None:
                            self._reader = DiskReader(disk, total_size, use_mmap=True)
                        recovered, file_counter = self._scan_ranges(
                            disk, scan_ranges, scan_total, total_size,
                            want_image, want_video, want_audio, want_document,
                            output_dir, file_counter, preview_only, start_time,
                            want_archive=want_archive,
                            want_executable=want_executable,
                            want_font=want_font,
                            want_database=want_database,
                            want_system=want_system,
                        )
                else:
                    # Brute-force: try parallel for large devices
                    parallel_result = None
                    if scan_total >= self._PARALLEL_THRESHOLD:
                        try:
                            from .parallel import (
                                split_sequential_for_workers,
                                optimal_worker_count,
                                ParallelScanConfig,
                            )
                            _pcfg = ParallelScanConfig()
                            n_workers = optimal_worker_count(scan_total, _pcfg)
                            seq_ranges = split_sequential_for_workers(
                                total_size, num_workers=n_workers,
                            )
                            if len(seq_ranges) > 1:
                                if self._reader:
                                    self._reader.close()
                                    self._reader = None
                                parallel_result = self._scan_parallel(
                                    raw_path, seq_ranges, scan_total, total_size,
                                    want_image, want_video, want_audio, want_document,
                                    output_dir, file_counter, preview_only, start_time,
                                    want_archive=want_archive,
                                    want_executable=want_executable,
                                    want_font=want_font,
                                    want_database=want_database,
                                    want_system=want_system,
                                )
                        except Exception as e:
                            logger.warning(
                                "Parallel scan failed, falling back: %s", e
                            )
                            parallel_result = None
                            self._reader = DiskReader(disk, total_size, use_mmap=True)

                    if parallel_result is not None:
                        recovered, file_counter = parallel_result
                    else:
                        if self._reader is None:
                            self._reader = DiskReader(disk, total_size, use_mmap=True)
                        recovered, file_counter = self._scan_sequential(
                            disk, total_size,
                            want_image, want_video, want_audio, want_document,
                            output_dir, file_counter, preview_only, start_time,
                            want_archive=want_archive,
                            want_executable=want_executable,
                            want_font=want_font,
                            want_database=want_database,
                            want_system=want_system,
                        )

                # ── STEP 4: Bifragment gap carving (second pass) ──
                if self._fragment_candidates and scan_ranges:
                    self.progress.status_message = (
                        f"🔗 Bifragment gap carving — "
                        f"Reassembling {len(self._fragment_candidates)} "
                        f"fragmented file(s)..."
                    )
                    self._notify_progress()
                    gap_results = self._bifragment_gap_carve(
                        disk, scan_ranges, total_size,
                        output_dir, file_counter, preview_only,
                    )
                    for rf in gap_results:
                        file_counter += 1
                        recovered.append(rf)
                        self.progress.files_found = len(recovered)
                        if self._on_file_found:
                            self._on_file_found(rf)
                    if gap_results:
                        logger.info(
                            "Bifragment gap carving recovered %d additional files",
                            len(gap_results),
                        )

                # Cleanup reader
                if self._reader:
                    self._reader.close()
                    self._reader = None

        except PermissionError:
            self.progress.status_message = (
                "❌ Permission denied. Run with:\n"
                "   sudo python main.py"
            )
            self._notify_progress()
            logger.error("Permission denied: %s", raw_path)
        except Exception as e:
            self.progress.status_message = f"❌ Error: {e}"
            self._notify_progress()
            logger.error("Scan error: %s", e, exc_info=True)

        # Finalize
        self.progress.is_scanning = False
        self.progress.scanned_bytes = scan_total
        self.progress.elapsed_time = time.time() - start_time
        self.progress.files_found = len(recovered)
        mode_tag = (
            f"🔬 Forensic ({fs_info.fs_type.upper()})"
            if scan_mode == "forensic" and fs_info
            else "⚡ Brute-force"
        )

        # Build performance summary
        perf_parts = []
        if self.progress.using_mmap:
            perf_parts.append("mmap")
        if self.progress.skipped_empty_bytes > 0:
            skipped_mb = self.progress.skipped_empty_bytes / (1024 * 1024)
            perf_parts.append(f"skipped {skipped_mb:.0f} MB empty/random")
        if self._entropy_skip_count > 0:
            perf_parts.append(f"entropy-filtered {self._entropy_skip_count} blocks")
        if self._drive_health:
            dh = self._drive_health
            if dh.is_ssd_with_trim:
                perf_parts.append(f"⚠️ SSD+TRIM ({dh.drive_type})")
            elif dh.drive_type:
                perf_parts.append(dh.drive_type)
        perf_tag = f"  [{', '.join(perf_parts)}]" if perf_parts else ""

        if not self.progress.is_cancelled:
            self.progress.status_message = (
                f"✅ {mode_tag} scan complete — Found {len(recovered)} "
                f"deleted file(s) "
                f"in {self.progress.elapsed_time:.1f}s{perf_tag}"
            )
        self._notify_progress()

        # Clear checkpoint on successful completion
        if not self.progress.is_cancelled:
            self.clear_checkpoint()

        return recovered

    # ─── Forensic scan: scan only unallocated ranges ─────────

    def _scan_ranges(
        self,
        disk,
        ranges: list[tuple[int, int]],
        scan_total: int,
        disk_size: int,
        want_image: bool,
        want_video: bool,
        want_audio: bool,
        want_document: bool,
        output_dir: str,
        file_counter: int,
        preview_only: bool,
        start_time: float,
        want_archive: bool = True,
        want_executable: bool = True,
        want_font: bool = True,
        want_database: bool = True,
        want_system: bool = True,
    ) -> tuple[list[RecoveredFile], int]:
        """Scan only the free/unallocated byte ranges (forensic mode)."""
        recovered: list[RecoveredFile] = []
        bytes_done = 0
        last_notify = 0.0

        for range_idx, (range_start, range_end) in enumerate(ranges):
            if self.progress.is_cancelled:
                break

            range_size = range_end - range_start
            offset = align_down(range_start)

            while offset < range_end and not self.progress.is_cancelled:
                # Read a chunk (but don't go past range boundary)
                read_size = min(self.READ_CHUNK, range_end - offset)
                if self._reader:
                    chunk = self._reader.read_at(offset, read_size)
                else:
                    disk.seek(offset)
                    chunk = disk.read(read_size)
                if not chunk:
                    break
                chunk_len = len(chunk)

                # ── Skip empty (zero-filled) blocks ──
                if is_empty_block(chunk):
                    self.progress.skipped_empty_bytes += chunk_len
                    offset += chunk_len
                    bytes_done += chunk_len
                    continue

                # ── Entropy-adaptive filtering ──
                # Skip blocks that are pure random/encrypted (entropy ~8.0)
                block_class = self._classify_block_entropy(chunk)
                if block_class == "skip":
                    self._entropy_skip_count += 1
                    self.progress.skipped_empty_bytes += chunk_len
                    offset += chunk_len
                    bytes_done += chunk_len
                    continue
                elif block_class == "empty":
                    self._entropy_skip_count += 1
                    self.progress.skipped_empty_bytes += chunk_len
                    offset += chunk_len
                    bytes_done += chunk_len
                    continue
                self._entropy_scan_count += 1

                # Search for signatures in this chunk
                new_files = self._search_chunk(
                    disk, chunk, offset, chunk_len, disk_size,
                    want_image, want_video, output_dir,
                    file_counter, preview_only,
                    want_audio=want_audio, want_document=want_document,
                    want_archive=want_archive,
                    want_executable=want_executable,
                    want_font=want_font,
                    want_database=want_database,
                    want_system=want_system,
                )
                for rf in new_files:
                    file_counter += 1
                    recovered.append(rf)
                    self.progress.files_found = len(recovered)
                    if self._on_file_found:
                        self._on_file_found(rf)

                # Advance within range (with overlap at chunk boundaries, not range boundaries)
                advance = chunk_len - self.OVERLAP
                if advance <= 0:
                    advance = chunk_len
                offset += advance
                bytes_done += min(advance, range_end - (offset - advance))

                # Progress
                now = time.time()
                if now - last_notify >= 0.3:
                    last_notify = now
                    elapsed = now - start_time
                    self.progress.scanned_bytes = min(bytes_done, scan_total)
                    self.progress.elapsed_time = elapsed
                    pct = self.progress.progress_percent
                    speed = self.progress.speed_mbps
                    self.progress.status_message = (
                        f"🔬 Forensic scan — "
                        f"Range {range_idx + 1}/{len(ranges)}  "
                        f"{_human_size(bytes_done)} / {_human_size(scan_total)}  "
                        f"({pct:.1f}%)  {speed:.0f} MB/s  —  "
                        f"Found: {len(recovered)} deleted files"
                    )
                    self._notify_progress()

                    # ── Periodic checkpoint save ──
                    if (bytes_done - self._last_checkpoint_bytes
                            >= self._checkpoint_interval):
                        self._last_checkpoint_bytes = bytes_done
                        self._save_checkpoint(
                            offset, file_counter,
                            [rf.offset for rf in recovered],
                            "forensic",
                            disk.name if hasattr(disk, "name") else "",
                        )

        return recovered, file_counter

    # ─── Brute-force scan: scan entire device sequentially ───

    def _scan_sequential(
        self,
        disk,
        total_size: int,
        want_image: bool,
        want_video: bool,
        want_audio: bool,
        want_document: bool,
        output_dir: str,
        file_counter: int,
        preview_only: bool,
        start_time: float,
        want_archive: bool = True,
        want_executable: bool = True,
        want_font: bool = True,
        want_database: bool = True,
        want_system: bool = True,
    ) -> tuple[list[RecoveredFile], int]:
        """Scan the entire device sequentially (brute-force fallback)."""
        recovered: list[RecoveredFile] = []
        offset = 0
        last_notify = 0.0

        while offset < total_size and not self.progress.is_cancelled:
            read_size = min(self.READ_CHUNK, total_size - offset)
            if self._reader:
                chunk = self._reader.read_at(offset, read_size)
            else:
                disk.seek(offset)
                chunk = disk.read(read_size)
            if not chunk:
                break
            chunk_len = len(chunk)

            # ── Skip empty (zero-filled) blocks ──
            if is_empty_block(chunk):
                self.progress.skipped_empty_bytes += chunk_len
                offset += chunk_len
                continue

            # ── Entropy-adaptive filtering ──
            block_class = self._classify_block_entropy(chunk)
            if block_class in ("skip", "empty"):
                self._entropy_skip_count += 1
                self.progress.skipped_empty_bytes += chunk_len
                offset += chunk_len
                continue
            self._entropy_scan_count += 1

            new_files = self._search_chunk(
                disk, chunk, offset, chunk_len, total_size,
                want_image, want_video, output_dir,
                file_counter, preview_only,
                want_audio=want_audio, want_document=want_document,
                want_archive=want_archive,
                want_executable=want_executable,
                want_font=want_font,
                want_database=want_database,
                want_system=want_system,
            )
            for rf in new_files:
                file_counter += 1
                recovered.append(rf)
                self.progress.files_found = len(recovered)
                if self._on_file_found:
                    self._on_file_found(rf)

            # Advance with overlap (sector-aligned)
            offset += chunk_len - self.OVERLAP
            if offset < 0:
                offset = 0
            offset = align_down(offset)

            # Progress
            now = time.time()
            elapsed = now - start_time
            self.progress.scanned_bytes = min(offset, total_size)
            self.progress.elapsed_time = elapsed

            if now - last_notify >= 0.3:
                last_notify = now
                pct = self.progress.progress_percent
                speed = self.progress.speed_mbps
                eta = self.progress.eta_seconds
                skipped_mb = self.progress.skipped_empty_bytes / (1024 * 1024)
                skip_info = f"  Skipped: {skipped_mb:.0f} MB empty" if skipped_mb > 0 else ""
                mmap_tag = " [mmap]" if self.progress.using_mmap else ""
                self.progress.status_message = (
                    f"⚡ Scanning raw sectors{mmap_tag}... "
                    f"{_human_size(offset)} / {_human_size(total_size)}  "
                    f"({pct:.1f}%)  "
                    f"{speed:.0f} MB/s  —  "
                    f"Found: {len(recovered)} deleted files{skip_info}"
                )
                self._notify_progress()

                # ── Periodic checkpoint save ──
                if (offset - self._last_checkpoint_bytes
                        >= self._checkpoint_interval):
                    self._last_checkpoint_bytes = offset
                    self._save_checkpoint(
                        offset, file_counter,
                        [rf.offset for rf in recovered],
                        "brute-force",
                        disk.name if hasattr(disk, "name") else "",
                    )

        return recovered, file_counter

    # ─── Parallel Scanning ───────────────────────────────────

    # Minimum bytes to justify multiprocessing overhead (~100 MB)
    _PARALLEL_THRESHOLD = 100 * 1024 * 1024

    def _scan_parallel(
        self,
        raw_path: str,
        ranges: list[tuple[int, int]],
        scan_total: int,
        disk_size: int,
        want_image: bool,
        want_video: bool,
        want_audio: bool,
        want_document: bool,
        output_dir: str,
        file_counter: int,
        preview_only: bool,
        start_time: float,
        want_archive: bool = True,
        want_executable: bool = True,
        want_font: bool = True,
        want_database: bool = True,
        want_system: bool = True,
    ) -> tuple[list[RecoveredFile], int]:
        """
        Parallel scanning across multiple worker processes.

        Splits ranges across N workers, each independently carving files.
        Results are merged and deduplicated by the coordinator (this method).
        """
        from .parallel import (
            ParallelScanConfig,
            WorkerResult,
            optimal_worker_count,
            split_ranges_for_workers,
            _worker_scan,
        )
        import multiprocessing as mp

        config = ParallelScanConfig(
            block_size=self.READ_CHUNK,
            overlap=self.OVERLAP,
            want_image=want_image,
            want_video=want_video,
            want_audio=want_audio,
            want_document=want_document,
            want_archive=want_archive,
            want_executable=want_executable,
            want_font=want_font,
            want_database=want_database,
            want_system=want_system,
        )

        num_workers = optimal_worker_count(scan_total, config)
        if num_workers <= 1:
            # Fall back to single-process scan
            return None  # Signal caller to use regular scan

        worker_range_sets = split_ranges_for_workers(ranges, num_workers)
        actual_workers = len(worker_range_sets)

        self.progress.status_message = (
            f"🚀 Parallel scan: {actual_workers} workers, "
            f"scanning {_human_size(scan_total)} across "
            f"{len(ranges)} ranges..."
        )
        self._notify_progress()
        logger.info(
            "Parallel scan: %d workers for %s in %d ranges",
            actual_workers, _human_size(scan_total), len(ranges),
        )

        # Create queues for results and progress
        result_queue = mp.Queue()
        progress_queue = mp.Queue()

        # Distribute file counter offsets so workers don't collide
        counter_base = file_counter
        counter_step = 100000  # Large gap to avoid collisions
        processes = []

        for i, worker_ranges in enumerate(worker_range_sets):
            p = mp.Process(
                target=_worker_scan,
                args=(
                    i,
                    raw_path,
                    worker_ranges,
                    config,
                    output_dir,
                    preview_only,
                    counter_base + i * counter_step,
                    result_queue,
                    progress_queue,
                    disk_size,  # Real device size (seek returns 0 on macOS raw devices)
                ),
                daemon=True,
            )
            processes.append(p)

        # Start all workers
        for p in processes:
            p.start()

        # Collect results
        recovered: list[RecoveredFile] = []
        workers_done = 0
        total_entropy_skipped = 0

        while workers_done < actual_workers and not self.progress.is_cancelled:
            # Drain progress queue
            while not progress_queue.empty():
                try:
                    prog = progress_queue.get_nowait()
                    # Update progress display
                    self.progress.status_message = (
                        f"🚀 Parallel scan [{actual_workers} workers] — "
                        f"Found: {len(recovered)} files  "
                        f"Worker {prog['worker_id']+1}: "
                        f"{_human_size(prog['bytes_scanned'])} scanned, "
                        f"{prog['files_found']} found"
                    )
                    self._notify_progress()
                except Exception:
                    break

            # Check for completed workers
            while not result_queue.empty():
                try:
                    result = result_queue.get_nowait()
                    if isinstance(result, WorkerResult):
                        workers_done += 1
                        total_entropy_skipped += result.entropy_skipped
                        logger.info(
                            "Worker %d complete: %d files in %.1fs "
                            "(%s scanned, %d entropy-skipped)",
                            result.worker_id, result.files_found,
                            result.elapsed,
                            _human_size(result.bytes_scanned),
                            result.entropy_skipped,
                        )

                        # Convert worker dicts to RecoveredFile objects
                        for rec in result.file_records:
                            sig = self._find_sig_by_ext(
                                rec["extension"], rec["category"]
                            )
                            if sig is None:
                                continue
                            # Deduplicate across workers
                            if self._dedup.is_duplicate_offset(rec["offset"]):
                                continue
                            self._dedup.register(rec["offset"])

                            rf = RecoveredFile(
                                signature=sig,
                                offset=rec["offset"],
                                size=rec["size"],
                                md5=rec.get("md5", ""),
                                recovered_path=rec.get("saved_path", ""),
                                raw_device_path=raw_path,
                                timestamp=time.time(),
                                is_valid=True,
                                is_saved=bool(rec.get("saved_path")),
                                source="carved",
                            )
                            file_counter += 1
                            recovered.append(rf)
                            self.progress.files_found = len(recovered)
                            if self._on_file_found:
                                self._on_file_found(rf)
                except Exception:
                    break

            time.sleep(0.1)

        # Wait for processes to finish
        for p in processes:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()

        self._entropy_skip_count += total_entropy_skipped
        self.progress.scanned_bytes = scan_total
        self.progress.elapsed_time = time.time() - start_time

        logger.info(
            "Parallel scan complete: %d files recovered, "
            "%d entropy-skipped blocks",
            len(recovered), total_entropy_skipped,
        )

        return recovered, file_counter

    def _find_sig_by_ext(self, ext: str, category: str) -> Optional[SignatureInfo]:
        """Find a SignatureInfo matching extension and category."""
        for sig in ALL_SIGNATURES:
            if sig.extension == ext and sig.category == category:
                return sig
        # Broader match
        for sig in ALL_SIGNATURES:
            if sig.extension == ext:
                return sig
        return None

    # ─── Bifragment Gap Carving (Second Pass) ────────────────

    def _bifragment_gap_carve(
        self,
        disk,
        scan_ranges: list[tuple[int, int]],
        disk_size: int,
        output_dir: str,
        file_counter: int,
        preview_only: bool,
    ) -> list[RecoveredFile]:
        """
        Bifragment gap carving — recover files split across non-contiguous
        clusters by searching for matching footers in other free ranges.

        Algorithm:
        1. For each orphan header (header found but no footer),
           search subsequent free ranges for the matching footer.
        2. If found, concatenate: [header_range_data] + [footer_range_data].
        3. Validate the reassembled file.

        This handles the common case where a file's data was stored in
        two non-contiguous cluster runs (bifragmented).
        """
        results: list[RecoveredFile] = []
        MAX_GAP_SEARCH = 10  # Search up to 10 subsequent ranges

        for frag in self._fragment_candidates:
            if self.progress.is_cancelled:
                break

            sig = frag["sig"]
            header_offset = frag["offset"]
            footer = sig.footer
            if not footer:
                continue  # Only for footer-based formats

            # Find which range the header is in
            header_range_idx = None
            for idx, (rs, re) in enumerate(scan_ranges):
                if rs <= header_offset < re:
                    header_range_idx = idx
                    break
            if header_range_idx is None:
                continue

            # Read the data from the header to end of its range
            header_range_end = scan_ranges[header_range_idx][1]
            first_fragment_size = min(
                header_range_end - header_offset,
                sig.max_size,
            )
            if self._reader:
                first_fragment = self._reader.read_at(header_offset, first_fragment_size)
            else:
                disk.seek(header_offset)
                first_fragment = disk.read(first_fragment_size)
            if not first_fragment:
                continue

            # Search subsequent free ranges for the footer
            found_footer = False
            for search_idx in range(
                header_range_idx + 1,
                min(header_range_idx + 1 + MAX_GAP_SEARCH, len(scan_ranges)),
            ):
                search_start, search_end = scan_ranges[search_idx]
                search_size = min(
                    search_end - search_start,
                    sig.max_size - len(first_fragment),
                )
                if search_size <= 0:
                    continue

                if self._reader:
                    second_fragment = self._reader.read_at(search_start, search_size)
                else:
                    disk.seek(search_start)
                    second_fragment = disk.read(search_size)
                if not second_fragment:
                    continue

                # Search for footer in the second fragment
                if sig.extension == "jpg":
                    footer_pos = second_fragment.rfind(footer)
                else:
                    footer_pos = second_fragment.find(footer)

                if footer_pos == -1:
                    continue

                # Found! Reassemble the file
                second_part = second_fragment[:footer_pos + len(footer)]
                reassembled = first_fragment + second_part

                if len(reassembled) < sig.min_size:
                    continue

                # Validate the reassembled file
                if not validate_carved_file(sig.extension, reassembled):
                    # Still include as damaged — it's better than nothing
                    damage = analyze_damage(sig.extension, reassembled)
                    md5 = compute_md5(reassembled)
                    rf = RecoveredFile(
                        signature=sig, offset=header_offset,
                        size=len(reassembled), md5=md5, recovered_path="",
                        raw_device_path=disk.name if hasattr(disk, "name") else "",
                        timestamp=time.time(), is_valid=False, is_saved=False,
                    )
                    rf.damage_report = damage
                    results.append(rf)
                    found_footer = True
                    break

                if self._dedup.is_duplicate_content(reassembled):
                    found_footer = True
                    break

                md5 = compute_md5(reassembled)
                saved_path = ""
                if not preview_only and output_dir:
                    saved_path = self._save_file(
                        reassembled, sig, file_counter + len(results), output_dir,
                    )

                rf = RecoveredFile(
                    signature=sig, offset=header_offset,
                    size=len(reassembled), md5=md5,
                    recovered_path=saved_path,
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=True,
                    is_saved=bool(saved_path),
                )
                results.append(rf)
                self._dedup.register(header_offset)
                logger.info(
                    "Bifragment carve: Reassembled %s from offset 0x%X "
                    "(gap at range %d → %d, total %s)",
                    sig.extension, header_offset,
                    header_range_idx, search_idx,
                    _human_size(len(reassembled)),
                )
                found_footer = True
                break

        return results

    # ─── Search one chunk for all signature types ────────────

    def _search_chunk(
        self,
        disk,
        chunk: bytes,
        offset: int,
        chunk_len: int,
        disk_size: int,
        want_image: bool,
        want_video: bool,
        output_dir: str,
        file_counter: int,
        preview_only: bool,
        want_audio: bool = True,
        want_document: bool = True,
        want_archive: bool = True,
        want_executable: bool = True,
        want_font: bool = True,
        want_database: bool = True,
        want_system: bool = True,
    ) -> list[RecoveredFile]:
        """Search a chunk for ALL known file signatures. Returns list of carved files."""
        found: list[RecoveredFile] = []

        # Category filter lookup
        _want = {
            "Image": want_image, "Video": want_video,
            "Audio": want_audio, "Document": want_document,
            "Archive": want_archive, "Executable": want_executable,
            "Font": want_font, "Database": want_database,
            "System": want_system,
        }

        # ── Fixed-header signatures ──
        for header_bytes, sig in self._header_sigs:
            if not _want.get(sig.category, True):
                continue

            for hit in self._find_all(chunk, header_bytes):
                abs_off = offset + hit
                if self._dedup.is_duplicate_offset(abs_off):
                    continue

                rf = self._carve_by_mode(
                    disk, abs_off, sig, output_dir,
                    file_counter + len(found), disk_size, preview_only,
                )
                if rf:
                    found.append(rf)
                    self._dedup.register(abs_off)
                    self._log_recovery(file_counter + len(found), rf)

        # ── RIFF-based formats (WebP, AVI) ──
        for hit in self._find_all(chunk, b"RIFF"):
            if hit + 12 > chunk_len:
                continue
            sub_type = bytes(chunk[hit + 8:hit + 12])
            sig = RIFF_TYPES.get(sub_type)
            if sig is None:
                continue
            if not _want.get(sig.category, True):
                continue

            abs_off = offset + hit
            if self._dedup.is_duplicate_offset(abs_off):
                continue

            rf = self._carve_riff_file(
                disk, abs_off, sig, output_dir,
                file_counter + len(found), disk_size, preview_only,
                chunk, hit, chunk_len,
            )
            if rf:
                found.append(rf)
                self._dedup.register(abs_off)
                self._log_recovery(file_counter + len(found), rf)

        # ── EBML-based: differentiate MKV vs WebM by doctype ──
        # (Already matched by fixed header \x1A\x45\xDF\xA3 above,
        #  but we refine the signature by checking the doctype string)
        # This is handled inside _carve_by_mode for EBML — see below.

        # ── MPEG-TS detection (0x47 sync byte every 188 bytes) ──
        if want_video:
            for hit in self._find_all(chunk, b"\x47"):
                # Only check at sector-aligned offsets to reduce false positives
                abs_off = offset + hit
                if abs_off % 188 != 0 and abs_off % 512 != 0:
                    continue
                if self._dedup.is_duplicate_offset(abs_off):
                    continue
                # Need 4 consecutive sync bytes at 188-byte intervals
                if hit + 188 * 4 <= chunk_len:
                    if is_mpeg_ts(chunk, hit):
                        rf = self._carve_maxread_file(
                            disk, abs_off, SIG_TS, output_dir,
                            file_counter + len(found), disk_size, preview_only,
                        )
                        if rf:
                            found.append(rf)
                            self._dedup.register(abs_off)
                            self._log_recovery(file_counter + len(found), rf)

        # ── ISO Base Media (ftyp → MP4/MOV/HEIC/3GP/M4V/AVIF) ──
        for hit in self._find_all(chunk, b"ftyp"):
            box_start = hit - 4
            if box_start < 0:
                continue
            abs_off = offset + box_start

            if box_start + 12 > chunk_len:
                continue
            box_size = struct.unpack(
                ">I", chunk[box_start:box_start + 4]
            )[0]
            if box_size < 8 or box_size > 8192:
                continue

            brand_start = hit + 4
            if brand_start + 4 > chunk_len:
                continue
            brand = bytes(chunk[brand_start:brand_start + 4])

            sig = FTYP_BRANDS.get(brand)
            if sig is None:
                sig = FTYP_BRANDS.get(brand.lower())
            if sig is None:
                continue

            if not _want.get(sig.category, True):
                continue

            if self._dedup.is_duplicate_offset(abs_off):
                continue

            rf = self._carve_isobmff_file(
                disk, abs_off, sig, output_dir,
                file_counter + len(found), disk_size, preview_only,
            )
            if rf:
                found.append(rf)
                self._dedup.register(abs_off)
                self._log_recovery(file_counter + len(found), rf)

        # ── ZIP-based detection (DOCX, XLSX, PPTX, EPUB, ODT, ODS, ODP, JAR, APK, or plain ZIP) ──
        if want_document or want_archive:
            from .signatures import (
                SIG_ZIP, SIG_DOCX, SIG_XLSX, SIG_PPTX,
                SIG_EPUB, SIG_ODT, SIG_ODS, SIG_ODP,
            )
            for hit in self._find_all(chunk, b"PK\x03\x04"):
                abs_off = offset + hit
                if self._dedup.is_duplicate_offset(abs_off):
                    continue
                # Peek at the first filename in the ZIP local file header
                # Offset 26: filename length (2 bytes LE), offset 30: filename
                sig = SIG_ZIP  # default
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
                        elif name_str == "[Content_Types].xml":
                            sig = SIG_DOCX  # Generic Office Open XML
                        elif name_str == "mimetype":
                            # EPUB or ODF — read the mimetype content
                            # The mimetype is stored uncompressed
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
                        elif name_str.startswith("META-INF/"):
                            # Could be ODT/ODS/ODP or JAR/APK
                            sig = SIG_ZIP  # default to ZIP

                if not _want.get(sig.category, True):
                    continue

                rf = self._carve_by_mode(
                    disk, abs_off, sig, output_dir,
                    file_counter + len(found), disk_size, preview_only,
                )
                if rf:
                    found.append(rf)
                    self._dedup.register(abs_off)
                    self._log_recovery(file_counter + len(found), rf)

        # ── FORM-based AIFF detection ──
        if want_audio:
            for hit in self._find_all(chunk, b"FORM"):
                if hit + 12 > chunk_len:
                    continue
                sub_type = bytes(chunk[hit + 8:hit + 12])
                if sub_type not in (b"AIFF", b"AIFC"):
                    continue
                abs_off = offset + hit
                if self._dedup.is_duplicate_offset(abs_off):
                    continue
                from .signatures import SIG_AIFF
                rf = self._carve_riff_file(
                    disk, abs_off, SIG_AIFF, output_dir,
                    file_counter + len(found), disk_size, preview_only,
                    chunk, hit, chunk_len,
                )
                if rf:
                    found.append(rf)
                    self._dedup.register(abs_off)
                    self._log_recovery(file_counter + len(found), rf)

        # ── TAR detection (ustar magic at offset 257 within a 512-byte block) ──
        if want_archive:
            from .signatures import SIG_TAR
            for hit in self._find_all(chunk, b"ustar"):
                # ustar should be at offset 257 within a 512-byte TAR header
                # So the TAR header starts at (hit - 257)
                tar_start = hit - 257
                if tar_start < 0:
                    continue
                abs_off = offset + tar_start
                # Verify alignment: TAR headers are on 512-byte boundaries
                if abs_off % 512 != 0:
                    continue
                if self._dedup.is_duplicate_offset(abs_off):
                    continue
                rf = self._carve_by_mode(
                    disk, abs_off, SIG_TAR, output_dir,
                    file_counter + len(found), disk_size, preview_only,
                )
                if rf:
                    found.append(rf)
                    self._dedup.register(abs_off)
                    self._log_recovery(file_counter + len(found), rf)

        # ── ISO 9660 detection (CD001 at offset 32769 = 0x8001) ──
        if want_archive:
            from .signatures import SIG_ISO
            for hit in self._find_all(chunk, b"CD001"):
                # CD001 appears at offset 32769 (sector 16 * 2048 + 1)
                iso_start = hit - 32769
                if iso_start < 0:
                    continue
                abs_off = offset + iso_start
                # Verify: ISO primary volume descriptor at sector 16
                if (abs_off % 2048) != 0:
                    continue
                if self._dedup.is_duplicate_offset(abs_off):
                    continue
                rf = self._carve_by_mode(
                    disk, abs_off, SIG_ISO, output_dir,
                    file_counter + len(found), disk_size, preview_only,
                )
                if rf:
                    found.append(rf)
                    self._dedup.register(abs_off)
                    self._log_recovery(file_counter + len(found), rf)

        return found

    # ─── Carve dispatcher by carve_mode ──────────────────────

    def _carve_by_mode(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
    ) -> Optional[RecoveredFile]:
        """Dispatch carving based on sig.carve_mode."""
        mode = sig.carve_mode
        if mode == "footer":
            return self._carve_footer_file(
                disk, offset, sig, output_dir, counter, disk_size, preview_only,
            )
        elif mode == "isobmff":
            return self._carve_isobmff_file(
                disk, offset, sig, output_dir, counter, disk_size, preview_only,
            )
        elif mode == "header":
            return self._carve_header_size_file(
                disk, offset, sig, output_dir, counter, disk_size, preview_only,
            )
        elif mode == "maxread":
            # For EBML (MKV/WebM), try to refine the sig
            if sig is SIG_MKV:
                sig = self._detect_ebml_doctype(disk, offset, sig)
            return self._carve_maxread_file(
                disk, offset, sig, output_dir, counter, disk_size, preview_only,
            )
        else:
            return self._carve_maxread_file(
                disk, offset, sig, output_dir, counter, disk_size, preview_only,
            )

    # ─── Detect EBML doctype (MKV vs WebM) ──────────────────

    def _detect_ebml_doctype(
        self, disk, offset: int, default_sig: SignatureInfo,
    ) -> SignatureInfo:
        """Read up to 64 bytes from EBML header and look for 'webm' doctype."""
        try:
            if self._reader:
                header = self._reader.read_at(offset, 64)
            else:
                disk.seek(offset)
                header = disk.read(64)
            if header and b"webm" in header:
                return SIG_WEBM
        except Exception:
            pass
        return default_sig

    # ─── Find all occurrences of a pattern in a chunk ────────

    @staticmethod
    def _find_all(data: bytes, pattern: bytes) -> list[int]:
        """Return all positions of `pattern` in `data`."""
        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions

    # ─── Carve JPEG / PNG (header → footer) ──────────────────

    def _carve_footer_file(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
    ) -> Optional[RecoveredFile]:
        """
        Carve a file that has a known footer (JPEG, PNG).
        Reads from `offset`, searches for the footer marker, trims.
        """
        try:
            max_read = min(sig.max_size, disk_size - offset)
            if max_read < sig.min_size:
                return None

            # Read in blocks, searching for footer
            footer = sig.footer
            assert footer is not None

            # Use mmap reader for zero-copy read if available
            if max_read <= 8 * 1024 * 1024:
                if self._reader:
                    data = self._reader.read_at(offset, max_read)
                else:
                    disk.seek(offset)
                    data = disk.read(max_read)
                if not data or len(data) < sig.min_size:
                    return None
                # Search for the LAST occurrence of the footer
                # (JPEG can have embedded thumbnails with their own FF D9)
                if sig.extension == "jpg":
                    # For JPEG, find the last FF D9
                    end_pos = data.rfind(footer)
                else:
                    # For PNG, find the first IEND
                    end_pos = data.find(footer)

                if end_pos != -1:
                    file_data = data[:end_pos + len(footer)]
                else:
                    # Footer not found — register as fragment candidate
                    # for bifragment gap carving second pass
                    self._fragment_candidates.append({
                        "type": "orphan_header",
                        "offset": offset,
                        "sig": sig,
                        "data_start": data[:min(1024, len(data))],
                        "read_size": len(data),
                    })
                    file_data = data
            else:
                # Large file — search in chunks
                file_data = self._search_footer_chunked(
                    disk, offset, footer, max_read, sig.extension,
                )
                if file_data is None or len(file_data) < sig.min_size:
                    return None

            if len(file_data) < sig.min_size:
                return None

            # Validate — if it fails, include as damaged instead of discarding
            if not validate_carved_file(sig.extension, file_data):
                damage = analyze_damage(sig.extension, file_data)
                md5 = compute_md5(file_data)
                rf = RecoveredFile(
                    signature=sig, offset=offset, size=len(file_data),
                    md5=md5, recovered_path="",
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=False, is_saved=False,
                )
                rf.damage_report = damage
                return rf

            # Dedup
            if self._dedup.is_duplicate_content(file_data):
                return None

            md5 = compute_md5(file_data)

            # Save or preview
            saved_path = ""
            if not preview_only and output_dir:
                saved_path = self._save_file(
                    file_data, sig, counter, output_dir
                )

            return RecoveredFile(
                signature=sig,
                offset=offset,
                size=len(file_data),
                md5=md5,
                recovered_path=saved_path,
                raw_device_path=disk.name if hasattr(disk, "name") else "",
                timestamp=time.time(),
                is_valid=True,
                is_saved=bool(saved_path),
            )

        except Exception as e:
            logger.debug("Carve failed at %d: %s", offset, e)
            return None

    def _search_footer_chunked(
        self, disk, offset: int, footer: bytes, max_read: int, ext: str,
    ) -> Optional[bytes]:
        """Search for footer in a large file by reading in chunks."""
        CHUNK = 4 * 1024 * 1024
        overlap = len(footer) + 16
        collected = bytearray()
        disk.seek(offset)
        read_total = 0
        last_footer_pos = -1

        while read_total < max_read:
            to_read = min(CHUNK, max_read - read_total)
            buf = disk.read(to_read)
            if not buf:
                break
            collected.extend(buf)
            read_total += len(buf)

            # Search in collected data
            search_start = max(0, len(collected) - len(buf) - overlap)
            if ext == "jpg":
                pos = bytes(collected).rfind(footer, search_start)
            else:
                pos = bytes(collected).find(footer, search_start)

            if pos != -1:
                last_footer_pos = pos
                if ext != "jpg":
                    # For non-JPEG, take the first footer found
                    return bytes(collected[:pos + len(footer)])

        if last_footer_pos != -1:
            return bytes(collected[:last_footer_pos + len(footer)])

        # Footer not found — return what we have (could be truncated)
        if len(collected) >= MIN_FILE_SIZE:
            return bytes(collected)
        return None

    # ─── Carve ISO Base Media (MP4/MOV/HEIC) ─────────────────

    def _carve_isobmff_file(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
    ) -> Optional[RecoveredFile]:
        """
        Carve an ISO Base Media file by walking its box/atom structure.
        This accurately determines the file size without needing a footer.
        """
        try:
            max_read = min(sig.max_size, disk_size - offset)
            if max_read < sig.min_size:
                return None

            # Walk the top-level boxes to determine total file size
            file_size = self._walk_isobmff_boxes(disk, offset, max_read)
            if file_size is None or file_size < sig.min_size:
                return None
            if file_size > max_read:
                file_size = max_read

            # Read the file data (use mmap reader if available)
            if self._reader:
                file_data = self._reader.read_at(offset, file_size)
            else:
                disk.seek(offset)
                file_data = disk.read(file_size)
            if len(file_data) < sig.min_size:
                return None

            # Validate
            if not validate_carved_file(sig.extension, file_data):
                # Include as damaged — never discard
                damage = analyze_damage(sig.extension, file_data)
                md5 = compute_md5(file_data)
                rf = RecoveredFile(
                    signature=sig, offset=offset, size=len(file_data),
                    md5=md5, recovered_path="",
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=False, is_saved=False,
                )
                rf.damage_report = damage
                return rf

            # Dedup
            if self._dedup.is_duplicate_content(file_data):
                return None

            md5 = compute_md5(file_data)

            saved_path = ""
            if not preview_only and output_dir:
                saved_path = self._save_file(
                    file_data, sig, counter, output_dir
                )

            return RecoveredFile(
                signature=sig,
                offset=offset,
                size=len(file_data),
                md5=md5,
                recovered_path=saved_path,
                raw_device_path=disk.name if hasattr(disk, "name") else "",
                timestamp=time.time(),
                is_valid=True,
                is_saved=bool(saved_path),
            )

        except Exception as e:
            logger.debug("ISO carve failed at %d: %s", offset, e)
            return None

    def _walk_isobmff_boxes(
        self, disk, start_offset: int, max_read: int,
    ) -> Optional[int]:
        """
        Walk top-level ISO Base Media boxes to determine file size.
        Returns the total size of the file (sum of all top-level boxes).
        """
        # Valid top-level box types in ISO Base Media files
        KNOWN_BOXES = {
            b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
            b"pdin", b"moof", b"mfra", b"meta", b"styp", b"sidx",
            b"ssix", b"prft", b"uuid",
        }

        pos = 0
        found_mdat = False
        box_count = 0

        while pos < max_read:
            # Use mmap reader for random access if available
            if self._reader:
                header = self._reader.read_at(start_offset + pos, 8)
            else:
                disk.seek(start_offset + pos)
                header = disk.read(8)
            if len(header) < 8:
                break

            box_size = struct.unpack(">I", header[:4])[0]
            box_type = header[4:8]

            # Handle extended size
            if box_size == 1:
                if self._reader:
                    ext_data = self._reader.read_at(start_offset + pos + 8, 8)
                else:
                    ext_data = disk.read(8)
                if len(ext_data) < 8:
                    break
                box_size = struct.unpack(">Q", ext_data)[0]
                if box_size < 16:
                    break
            elif box_size == 0:
                # Box extends to end — use a reasonable cap
                if found_mdat:
                    return pos  # Already past mdat, stop here
                # This is the last box, extends to EOF
                # We don't know the real end, so cap it
                remaining = min(max_read - pos, 500 * 1024 * 1024)
                return pos + remaining

            if box_size < 8:
                break

            # Check if box type is known
            if box_type not in KNOWN_BOXES:
                # Unknown box type — could be end of file or corruption
                # If we've found at least ftyp + one other box, accept what we have
                if box_count >= 2:
                    return pos
                break

            box_count += 1
            if box_type == b"mdat":
                found_mdat = True

            # If we're past mdat and see another known box, keep going
            pos += box_size

            if pos > max_read:
                pos = max_read
                break

        # We need at least ftyp + mdat (or ftyp + moov) for a valid file
        if box_count >= 2 and pos >= MIN_FILE_SIZE:
            return pos

        return None

    # ─── Carve RIFF-based files (WebP, AVI) ───────────────────

    def _carve_riff_file(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
        chunk: bytes = b"",
        hit: int = 0,
        chunk_len: int = 0,
    ) -> Optional[RecoveredFile]:
        """
        Carve a RIFF-based file.  The file size is encoded in bytes 4-8
        of the RIFF header (LE uint32 = size of data after the 8-byte header).
        Total file size = riff_size + 8.
        """
        try:
            # Try to read size from the chunk first
            if chunk and hit + 8 <= chunk_len:
                riff_data_size = struct.unpack("<I", chunk[hit + 4:hit + 8])[0]
            else:
                # Read from disk
                if self._reader:
                    hdr = self._reader.read_at(offset, 12)
                else:
                    disk.seek(offset)
                    hdr = disk.read(12)
                if len(hdr) < 12:
                    return None
                riff_data_size = struct.unpack("<I", hdr[4:8])[0]

            file_size = riff_data_size + 8  # RIFF header is 8 bytes
            if file_size < sig.min_size or file_size > sig.max_size:
                return None
            if offset + file_size > disk_size:
                file_size = disk_size - offset

            # Read full file
            if self._reader:
                file_data = self._reader.read_at(offset, file_size)
            else:
                disk.seek(offset)
                file_data = disk.read(file_size)

            if len(file_data) < sig.min_size:
                return None

            if not validate_carved_file(sig.extension, file_data):
                # Include as damaged — never discard
                damage = analyze_damage(sig.extension, file_data)
                md5 = compute_md5(file_data)
                rf = RecoveredFile(
                    signature=sig, offset=offset, size=len(file_data),
                    md5=md5, recovered_path="",
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=False, is_saved=False,
                )
                rf.damage_report = damage
                return rf
            if self._dedup.is_duplicate_content(file_data):
                return None

            md5 = compute_md5(file_data)
            saved_path = ""
            if not preview_only and output_dir:
                saved_path = self._save_file(file_data, sig, counter, output_dir)

            return RecoveredFile(
                signature=sig, offset=offset, size=len(file_data),
                md5=md5, recovered_path=saved_path,
                raw_device_path=disk.name if hasattr(disk, "name") else "",
                timestamp=time.time(), is_valid=True, is_saved=bool(saved_path),
            )
        except Exception as e:
            logger.debug("RIFF carve failed at %d: %s", offset, e)
            return None

    # ─── Carve files with size in header (BMP, ICO) ──────────

    def _carve_header_size_file(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
    ) -> Optional[RecoveredFile]:
        """
        Carve a file whose size is encoded in its header.
        BMP: 4-byte LE at offset 2
        ICO: computed from directory entries
        """
        try:
            # Read enough header to determine size
            if self._reader:
                hdr = self._reader.read_at(offset, 256)
            else:
                disk.seek(offset)
                hdr = disk.read(256)

            if len(hdr) < 14:
                return None

            # ── Early structural validation BEFORE computing size ──
            # This prevents false-positive matches (e.g. random 'BM')
            # from reading garbage size values and creating huge reads.
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
                # Each ICO directory entry is 16 bytes, starting at offset 6
                dir_end = 6 + count * 16
                if len(hdr) < dir_end:
                    # Need more data for directory
                    if self._reader:
                        hdr = self._reader.read_at(offset, dir_end + 16)
                    else:
                        disk.seek(offset)
                        hdr = disk.read(dir_end + 16)
                    if len(hdr) < dir_end:
                        return None
                # Find the maximum extent of image data
                max_end = dir_end
                for i in range(count):
                    entry_off = 6 + i * 16
                    if entry_off + 16 > len(hdr):
                        break
                    img_size = struct.unpack("<I", hdr[entry_off + 8:entry_off + 12])[0]
                    img_offset = struct.unpack("<I", hdr[entry_off + 12:entry_off + 16])[0]
                    end = img_offset + img_size
                    if end > max_end:
                        max_end = end
                file_size = max_end
            else:
                # Unknown header-size format, fall back to maxread
                return self._carve_maxread_file(
                    disk, offset, sig, output_dir, counter, disk_size, preview_only,
                )

            if file_size < sig.min_size or file_size > sig.max_size:
                return None
            if offset + file_size > disk_size:
                file_size = disk_size - offset

            # Read full file
            if self._reader:
                file_data = self._reader.read_at(offset, file_size)
            else:
                disk.seek(offset)
                file_data = disk.read(file_size)

            if len(file_data) < sig.min_size:
                return None

            if not validate_carved_file(sig.extension, file_data):
                # Include as damaged — never discard
                damage = analyze_damage(sig.extension, file_data)
                md5 = compute_md5(file_data)
                rf = RecoveredFile(
                    signature=sig, offset=offset, size=len(file_data),
                    md5=md5, recovered_path="",
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=False, is_saved=False,
                )
                rf.damage_report = damage
                return rf
            if self._dedup.is_duplicate_content(file_data):
                return None

            md5 = compute_md5(file_data)
            saved_path = ""
            if not preview_only and output_dir:
                saved_path = self._save_file(file_data, sig, counter, output_dir)

            return RecoveredFile(
                signature=sig, offset=offset, size=len(file_data),
                md5=md5, recovered_path=saved_path,
                raw_device_path=disk.name if hasattr(disk, "name") else "",
                timestamp=time.time(), is_valid=True, is_saved=bool(saved_path),
            )
        except Exception as e:
            logger.debug("Header-size carve failed at %d: %s", offset, e)
            return None

    # ─── Carve files by max-read (TIFF, PSD, RAW, MKV, FLV, WMV, etc.) ──

    def _carve_maxread_file(
        self,
        disk,
        offset: int,
        sig: SignatureInfo,
        output_dir: str,
        counter: int,
        disk_size: int,
        preview_only: bool,
    ) -> Optional[RecoveredFile]:
        """
        Carve a file by reading up to max_size bytes.
        Used for formats where we cannot determine exact end-of-file
        from header or footer alone (TIFF, PSD, MKV, FLV, WMV, etc.).

        Strategy:
        1. Try format-specific size detection (EBML, ASF/WMV, FLV, etc.)
        2. Fallback: read conservatively, trim at next known header boundary.
        """
        try:
            max_read = min(sig.max_size, disk_size - offset)
            if max_read < sig.min_size:
                return None

            # ── Format-specific exact-size detection ─────────
            exact_size = self._try_exact_size(disk, offset, sig, max_read)
            if exact_size is not None and sig.min_size <= exact_size <= max_read:
                if self._reader:
                    file_data = self._reader.read_at(offset, exact_size)
                else:
                    disk.seek(offset)
                    file_data = disk.read(exact_size)
            else:
                # ── Conservative cap for formats without exact size ──
                # For image formats: cap at 50 MB (most images are under 50 MB)
                # For video formats: use a stepped approach
                if sig.category == "Image":
                    initial_cap = min(max_read, 50 * 1024 * 1024)
                else:
                    initial_cap = min(max_read, 200 * 1024 * 1024)

                if self._reader:
                    file_data = self._reader.read_at(offset, initial_cap)
                else:
                    disk.seek(offset)
                    file_data = disk.read(initial_cap)

            if not file_data or len(file_data) < sig.min_size:
                return None

            # ── Trim at next file header boundary ────────────
            # Use a larger search start to avoid false positive headers
            # that are part of the current file (e.g. TIFF IFDs can contain
            # JPEG thumbnail data with \xFF\xD8\xFF header).
            # Video files need a much larger skip (256 KB+) because embedded
            # data / metadata at the start often contains false matches.
            if sig.category == "Video":
                search_start = max(sig.min_size, 256 * 1024)  # 256 KB
            elif sig.category == "Audio":
                search_start = max(sig.min_size, 128 * 1024)  # 128 KB
            else:
                search_start = max(sig.min_size, 64 * 1024)   # 64 KB
            trim_pos = self._find_next_header(file_data, search_start)
            if trim_pos is not None and trim_pos > sig.min_size:
                file_data = file_data[:trim_pos]

            # ── Content-aware entropy trimming ───────────────
            # Detect where file content ends by analyzing entropy changes
            file_data = self._smart_entropy_trim(file_data, sig)

            if len(file_data) < sig.min_size:
                return None

            if not validate_carved_file(sig.extension, file_data):
                # Include as damaged — never discard
                damage = analyze_damage(sig.extension, file_data)
                md5 = compute_md5(file_data)
                rf = RecoveredFile(
                    signature=sig, offset=offset, size=len(file_data),
                    md5=md5, recovered_path="",
                    raw_device_path=disk.name if hasattr(disk, "name") else "",
                    timestamp=time.time(), is_valid=False, is_saved=False,
                )
                rf.damage_report = damage
                return rf
            if self._dedup.is_duplicate_content(file_data):
                return None

            md5 = compute_md5(file_data)
            saved_path = ""
            if not preview_only and output_dir:
                saved_path = self._save_file(file_data, sig, counter, output_dir)

            return RecoveredFile(
                signature=sig, offset=offset, size=len(file_data),
                md5=md5, recovered_path=saved_path,
                raw_device_path=disk.name if hasattr(disk, "name") else "",
                timestamp=time.time(), is_valid=True, is_saved=bool(saved_path),
            )
        except Exception as e:
            logger.debug("Maxread carve failed at %d: %s", offset, e)
            return None

    def _try_exact_size(
        self, disk, offset: int, sig: SignatureInfo, max_read: int,
    ) -> Optional[int]:
        """Attempt format-specific exact size detection for maxread formats."""
        try:
            ext = sig.extension
            # Read the header region
            if self._reader:
                hdr = self._reader.read_at(offset, min(256, max_read))
            else:
                disk.seek(offset)
                hdr = disk.read(min(256, max_read))
            if not hdr or len(hdr) < 16:
                return None

            # ── FLV: header + tag walking ──
            if ext == "flv" and hdr[:3] == b"FLV":
                data_offset = struct.unpack(">I", hdr[5:9])[0]
                if 9 <= data_offset <= 1024:
                    return self._walk_flv_tags(disk, offset, data_offset, max_read)

            # ── WMV/ASF: object size in header ──
            if ext == "wmv" and len(hdr) >= 24:
                # ASF header object: 16-byte GUID + 8-byte size (total file size)
                file_sz = struct.unpack("<Q", hdr[16:24])[0]
                if sig.min_size <= file_sz <= max_read:
                    return file_sz

            # ── OGV/OGG: walk OGG pages ──
            if ext == "ogv" and hdr[:4] == b"OggS":
                return self._walk_ogg_pages(disk, offset, max_read)

            # ── RealMedia: header has file size ──
            if ext == "rm" and hdr[:4] == b".RMF" and len(hdr) >= 18:
                file_sz = struct.unpack(">I", hdr[14:18])[0]
                if sig.min_size <= file_sz <= max_read:
                    return file_sz

            # ── SWF: file length in header ──
            if ext == "swf" and len(hdr) >= 8 and hdr[:3] in (b"FWS", b"CWS", b"ZWS"):
                file_sz = struct.unpack("<I", hdr[4:8])[0]
                if sig.min_size <= file_sz <= max_read:
                    return file_sz

            # ── MPEG-TS: walk 188-byte packets ──
            if ext == "ts" and len(hdr) >= 1 and hdr[0] == 0x47:
                return self._walk_mpeg_ts_packets(disk, offset, max_read)

            # ── MKV / WebM (EBML): read Segment element size ──
            if ext in ("mkv", "webm") and hdr[:4] == b"\x1A\x45\xDF\xA3":
                return self._read_ebml_size(disk, offset, max_read)

        except Exception:
            pass
        return None

    def _walk_mpeg_ts_packets(
        self, disk, offset: int, max_read: int,
    ) -> Optional[int]:
        """Walk 188-byte MPEG-TS packets to find stream end."""
        try:
            cap = min(max_read, 200 * 1024 * 1024)
            if self._reader:
                data = self._reader.read_at(offset, cap)
            else:
                disk.seek(offset)
                data = disk.read(cap)
            if not data:
                return None
            pos = 0
            while pos + 188 <= len(data):
                if data[pos] != 0x47:
                    break
                pos += 188
            return pos if pos > 0 else None
        except Exception:
            return None

    def _read_ebml_size(
        self, disk, offset: int, max_read: int,
    ) -> Optional[int]:
        """Try to read EBML header + Segment element to get MKV/WebM size."""
        try:
            cap = min(max_read, 1024)
            if self._reader:
                data = self._reader.read_at(offset, cap)
            else:
                disk.seek(offset)
                data = disk.read(cap)
            if not data or len(data) < 12:
                return None
            # Skip EBML header element: ID=0x1A45DFA3, read VINT size
            pos = 4
            ebml_hdr_sz, consumed = self._read_ebml_vint(data, pos)
            if ebml_hdr_sz is None:
                return None
            pos += consumed + ebml_hdr_sz
            # Next element should be Segment (ID = 0x18538067)
            if pos + 4 > len(data):
                return None
            if data[pos:pos + 4] == b"\x18\x53\x80\x67":
                seg_sz, consumed = self._read_ebml_vint(data, pos + 4)
                if seg_sz is not None and seg_sz < max_read:
                    total = pos + 4 + consumed + seg_sz
                    if total <= max_read:
                        return total
            return None
        except Exception:
            return None

    @staticmethod
    def _read_ebml_vint(data: bytes, pos: int) -> tuple:
        """Read an EBML variable-length integer. Returns (value, bytes_consumed) or (None, 0)."""
        if pos >= len(data):
            return None, 0
        first = data[pos]
        if first == 0:
            return None, 0
        length = 1
        mask = 0x80
        while mask and not (first & mask):
            length += 1
            mask >>= 1
        if pos + length > len(data):
            return None, 0
        value = first & (mask - 1)
        for i in range(1, length):
            value = (value << 8) | data[pos + i]
        # Check for "unknown size" marker (all data bits set to 1)
        if value == (1 << (7 * length)) - 1:
            return None, 0
        return value, length

    def _walk_flv_tags(
        self, disk, offset: int, data_offset: int, max_read: int,
    ) -> Optional[int]:
        """Walk FLV tags to determine file size."""
        try:
            # Read in chunks and walk tag headers
            pos = data_offset + 4  # skip first PreviousTagSize (4 bytes)
            if self._reader:
                data = self._reader.read_at(offset, min(max_read, 50 * 1024 * 1024))
            else:
                disk.seek(offset)
                data = disk.read(min(max_read, 50 * 1024 * 1024))
            if not data:
                return None
            last_valid = data_offset
            while pos + 11 < len(data):
                tag_type = data[pos]
                if tag_type not in (8, 9, 18):  # audio, video, script
                    break
                tag_data_size = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
                tag_total = 11 + tag_data_size
                pos += tag_total
                if pos + 4 > len(data):
                    break
                # PreviousTagSize
                pos += 4
                last_valid = pos
            return last_valid if last_valid > data_offset else None
        except Exception:
            return None

    def _walk_ogg_pages(
        self, disk, offset: int, max_read: int,
    ) -> Optional[int]:
        """Walk OGG pages to determine container size."""
        try:
            cap = min(max_read, 50 * 1024 * 1024)
            if self._reader:
                data = self._reader.read_at(offset, cap)
            else:
                disk.seek(offset)
                data = disk.read(cap)
            if not data:
                return None
            pos = 0
            last_valid = 0
            while pos + 27 < len(data):
                if data[pos:pos + 4] != b"OggS":
                    break
                n_segments = data[pos + 26]
                if pos + 27 + n_segments > len(data):
                    break
                page_data_size = sum(data[pos + 27 + i] for i in range(n_segments))
                page_size = 27 + n_segments + page_data_size
                pos += page_size
                last_valid = pos
            return last_valid if last_valid > 0 else None
        except Exception:
            return None

    # Signatures that are too short or too common in binary data to be
    # reliable "next file" boundary markers.  These are skipped during
    # _find_next_header to avoid premature trimming.
    _AMBIGUOUS_HEADERS: set[bytes] = {
        b"BM",                          # 2 bytes — matches everywhere
        b"\x00\x00\x01\x00",          # ICO — 4 bytes starting with zeros
        b"\x00\x00\x01\xBA",          # MPEG-PS pack — appears inside MPEG data
        b"\x00\x00\x01\xB3",          # MPEG-1 seq — appears inside MPEG data
        b"\x00\x00\x01\xBB",          # MPEG system header — appears inside MPEG data
        b"\x00\x00\x01\xB8",          # MPEG GOP — appears inside MPEG data
        b"II\x2A\x00",                 # TIFF LE — 4 bytes, common
        b"MM\x00\x2A",                 # TIFF BE — 4 bytes, common
        b"FWS",                          # SWF — 3 ASCII chars
        b"CWS",                          # SWF — 3 ASCII chars
        b"\xFF\xFB",                    # MP3 frame sync — 2 bytes, very common
        b"\xFF\xFA",                    # MP3 frame sync — 2 bytes
        b"\xFF\xF3",                    # MP3 frame sync — 2 bytes
        b"\xFF\xF2",                    # MP3 frame sync — 2 bytes
    }

    def _smart_entropy_trim(
        self, data: bytes, sig: SignatureInfo,
    ) -> bytes:
        """
        Content-aware entropy trimming for maxread-carved files.

        Uses a sliding window to detect sudden entropy transitions that
        indicate the boundary between file content and garbage/next-file data.

        Also detects large zero-filled regions at the end (common in
        partially overwritten files) and trims them.
        """
        if len(data) < sig.min_size * 2:
            return data  # Too small to trim meaningfully

        # ── Step 1: Trim trailing zeros ──
        # Find last non-zero byte
        end = len(data)
        # Check the last 4K block
        tail = data[-4096:] if len(data) >= 4096 else data
        if all(b == 0 for b in tail):
            # Search backwards for non-zero content
            search_end = max(sig.min_size, len(data) - 10 * 1024 * 1024)
            for pos in range(len(data) - 1, search_end, -4096):
                block_start = max(0, pos - 4096)
                block = data[block_start:pos]
                if any(b != 0 for b in block):
                    # Round up to next sector boundary
                    end = ((pos + 511) // 512) * 512
                    break
            data = data[:end]

        # ── Step 2: Sliding-window entropy analysis ──
        # Detect sharp entropy drops that indicate file boundary
        WINDOW = 32 * 1024   # 32 KB window
        STEP = 16 * 1024     # 16 KB step
        min_scan = max(sig.min_size, 64 * 1024)  # Don't trim below this

        if len(data) < min_scan + WINDOW * 3:
            return data

        # Calculate baseline entropy from first few windows
        baseline_samples = []
        for i in range(0, min(min_scan, WINDOW * 4), WINDOW):
            if i + WINDOW <= len(data):
                ent = calculate_entropy(data[i:i + WINDOW])
                baseline_samples.append(ent)

        if not baseline_samples:
            return data

        baseline_ent = sum(baseline_samples) / len(baseline_samples)
        if baseline_ent < 2.0:
            return data  # Low entropy file, don't trim by entropy

        # Scan from min_scan to end looking for sharp entropy changes
        prev_ent = baseline_ent
        for pos in range(min_scan, len(data) - WINDOW, STEP):
            window = data[pos:pos + WINDOW]
            ent = calculate_entropy(window)

            # Detect: entropy drops to near-zero (zero-filled region)
            if ent < 0.5 and prev_ent > 3.0:
                return data[:pos]

            # Detect: sharp entropy change (>3.0 drop from baseline)
            # indicates transition to different data
            if baseline_ent > 5.0 and ent < baseline_ent - 3.5:
                return data[:pos]

            prev_ent = ent

        return data

    def _find_next_header(self, data: bytes, start: int) -> Optional[int]:
        """
        Search for the next *high-confidence* file header within data[start:].
        Returns the offset within data if found, else None.

        Only uses signatures that are long enough and distinctive enough
        to be reliable boundary markers.  Short / ambiguous patterns
        (BM, ICO, MPEG start codes, TIFF) are skipped because they
        appear frequently inside other file formats.
        """
        best = None
        search_data = data[start:]

        # Only use high-confidence headers (skip ambiguous ones)
        for header_bytes, _sig in HEADER_SIGNATURES:
            if header_bytes in self._AMBIGUOUS_HEADERS:
                continue
            pos = search_data.find(header_bytes)
            if pos != -1:
                actual_pos = start + pos
                if best is None or actual_pos < best:
                    best = actual_pos

        # RIFF — validate with sub-type at offset +8
        idx = 0
        while idx < len(search_data):
            pos = search_data.find(b"RIFF", idx)
            if pos == -1:
                break
            # Must have sub-type we recognise (WEBP, AVI )
            sub_off = pos + 8
            if sub_off + 4 <= len(search_data):
                sub = search_data[sub_off:sub_off + 4]
                if sub in RIFF_TYPES:
                    actual_pos = start + pos
                    if best is None or actual_pos < best:
                        best = actual_pos
                    break
            idx = pos + 1

        # ftyp — validate box size is reasonable (8..65536)
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

    # ─── File saving ──────────────────────────────────────────

    @staticmethod
    def _save_file(
        data: bytes,
        sig: SignatureInfo,
        counter: int,
        output_dir: str,
    ) -> str:
        """Save carved file to disk, organized by category."""
        subdir = os.path.join(output_dir, sig.category)
        os.makedirs(subdir, exist_ok=True)
        filename = f"recovered_{counter + 1:06d}.{sig.extension}"
        path = os.path.join(subdir, filename)
        # Avoid overwriting
        if os.path.exists(path):
            base, ext = os.path.splitext(path)
            i = 1
            while os.path.exists(path):
                path = f"{base}_{i}{ext}"
                i += 1
        with open(path, "wb") as f:
            f.write(data)
        return path

    # ─── Logging ──────────────────────────────────────────────

    def _log_recovery(self, counter: int, rf: RecoveredFile):
        self._recovery_log.append({
            "file_number": counter,
            "type": rf.description,
            "extension": rf.extension,
            "offset": rf.offset,
            "offset_hex": f"0x{rf.offset:X}",
            "sector": rf.sector,
            "size": rf.size,
            "size_human": rf.size_human,
            "md5": rf.md5,
            "saved_to": rf.recovered_path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    def _notify_progress(self):
        if self._on_progress:
            self._on_progress(self.progress)

    # ─────────────────────────────────────────────────────────
    #  Device Resolution
    # ─────────────────────────────────────────────────────────

    def _resolve_raw_device(self, path: str) -> Optional[str]:
        """
        Resolve a path to its raw block device.
        Accepts: disk image file, raw device path, or mount point.
        """
        # Disk image file
        if os.path.isfile(path):
            return path

        # Already a raw device
        if path.startswith("/dev/") or path.startswith("\\\\.\\"):
            if os.path.exists(path):
                return path
            return None

        system = platform.system()
        if system == "Darwin":
            return self._resolve_macos(path)
        elif system == "Linux":
            return self._resolve_linux(path)
        elif system == "Windows":
            return self._resolve_windows(path)
        return None

    def _resolve_macos(self, mount_point: str) -> Optional[str]:
        """macOS: mount point → /dev/rdiskN (raw character device for speed)."""
        try:
            r = subprocess.run(
                ["diskutil", "info", mount_point],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                if "Device Node" in line:
                    dev = line.split(":")[-1].strip()
                    # Prefer raw device for faster reads
                    raw = dev.replace("/dev/disk", "/dev/rdisk")
                    if os.path.exists(raw):
                        return raw
                    if os.path.exists(dev):
                        return dev
        except Exception:
            pass

        # Fallback: try df
        try:
            r = subprocess.run(
                ["df", mount_point],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines()[1:]:
                dev = line.split()[0]
                if dev.startswith("/dev/"):
                    raw = dev.replace("/dev/disk", "/dev/rdisk")
                    if os.path.exists(raw):
                        return raw
                    return dev
        except Exception:
            pass
        return None

    def _resolve_linux(self, mount_point: str) -> Optional[str]:
        try:
            r = subprocess.run(
                ["findmnt", "-no", "SOURCE", mount_point],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                dev = r.stdout.strip()
                if dev and os.path.exists(dev):
                    return dev
        except Exception:
            pass

        # Fallback: /proc/mounts
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == mount_point:
                        if os.path.exists(parts[0]):
                            return parts[0]
        except Exception:
            pass
        return None

    def _resolve_windows(self, drive: str) -> Optional[str]:
        letter = drive.rstrip(":\\")
        raw = f"\\\\.\\{letter}:"
        try:
            with open(raw, "rb") as f:
                f.read(512)
            return raw
        except Exception:
            pass
        return None

    def _get_device_size(self, path: str) -> int:
        """Get total byte size of a device or file."""
        # File
        if os.path.isfile(path):
            return os.path.getsize(path)

        system = platform.system()

        # macOS: diskutil info
        if system == "Darwin":
            try:
                r = subprocess.run(
                    ["diskutil", "info", path],
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines():
                    if "Disk Size" in line or "Total Size" in line:
                        m = re.search(r"\((\d+)\s+[Bb]ytes", line)
                        if m:
                            return int(m.group(1))
            except Exception:
                pass

        # Linux: /sys/block/*/size or blockdev --getsize64
        if system == "Linux":
            try:
                r = subprocess.run(
                    ["blockdev", "--getsize64", path],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0:
                    return int(r.stdout.strip())
            except Exception:
                pass

        # Windows: PowerShell Get-Partition or WMI
        if system == "Windows":
            try:
                # Extract drive letter from path like \\.\C:
                letter = path.replace("\\\\.\\", "").rstrip(":\\:")
                if letter:
                    r = subprocess.run(
                        ["powershell", "-Command",
                         f"(Get-Partition -DriveLetter {letter}).Size"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if r.returncode == 0 and r.stdout.strip():
                        return int(r.stdout.strip())
            except Exception:
                pass

        # Fallback: seek to end
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                return f.tell()
        except Exception:
            pass

        # Fallback: statvfs (for mount points — Unix)
        try:
            st = os.statvfs(path)
            return st.f_blocks * st.f_frsize
        except (OSError, AttributeError):
            pass

        # Fallback: shutil.disk_usage (cross-platform, works on mount points)
        try:
            import shutil
            usage = shutil.disk_usage(path)
            return usage.total
        except (OSError, TypeError):
            pass

        return 0

    # ─────────────────────────────────────────────────────────
    #  Drive Listing
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def list_drives() -> list[DriveInfo]:
        system = platform.system()
        if system == "Darwin":
            return DiskScanner._list_macos()
        elif system == "Linux":
            return DiskScanner._list_linux()
        elif system == "Windows":
            return DiskScanner._list_windows()
        return []

    @staticmethod
    def _list_macos() -> list[DriveInfo]:
        drives: list[DriveInfo] = []

        # Helper: detect drive type from diskutil info
        def _detect_type(info: dict) -> tuple[str, str]:
            """Returns (drive_type, bus_protocol)."""
            protocol = info.get("DeviceProtocol", "").lower()
            is_ssd = info.get("SolidState", False)
            is_removable = info.get("Removable", False) or info.get("RemovableMedia", False)
            bus = info.get("BusProtocol", "") or info.get("DeviceProtocol", "")

            if "nvme" in protocol or "nvme" in bus.lower():
                return "NVMe SSD", "NVMe"
            elif "pcie" in protocol or "pci" in protocol:
                if is_ssd:
                    return "PCIe SSD", "PCIe"
                return "PCIe", "PCIe"
            elif "usb" in protocol:
                if is_ssd:
                    return "External SSD (USB)", "USB"
                elif is_removable:
                    # Check if it's an SD card reader
                    model = info.get("MediaName", "").lower()
                    if any(k in model for k in ("sd", "card", "mmc")):
                        return "SD Card", "USB"
                    return "USB Drive", "USB"
                return "USB Drive", "USB"
            elif "thunderbolt" in protocol:
                if is_ssd:
                    return "External SSD (Thunderbolt)", "Thunderbolt"
                return "HDD", "Thunderbolt"
            elif "firewire" in protocol or "1394" in protocol:
                if is_ssd:
                    return "External SSD (FireWire)", "FireWire"
                return "HDD", "FireWire"
            elif is_ssd:
                return "SSD", bus or "SATA"
            else:
                return "HDD" if not is_removable else "USB Drive", bus or "SATA"

        # Boot volume
        try:
            st = os.statvfs("/")
            boot_type = "SSD"
            boot_bus = "APFS"
            # Try to get boot disk type
            try:
                br = subprocess.run(
                    ["diskutil", "info", "-plist", "/"],
                    capture_output=True, timeout=10,
                )
                if br.returncode == 0:
                    import plistlib
                    binfo = plistlib.loads(br.stdout)
                    boot_type, boot_bus = _detect_type(binfo)
            except Exception:
                pass

            drives.append(DriveInfo(
                device_path="/dev/rdisk1",
                mount_point="/",
                label="Macintosh HD",
                filesystem="APFS",
                total_size=st.f_blocks * st.f_frsize,
                free_size=st.f_bfree * st.f_frsize,
                drive_type=boot_type,
                bus_protocol=boot_bus,
            ))
        except OSError:
            pass

        # All volumes (external + internal non-boot)
        try:
            import plistlib
            # Get ALL disks, not just external
            for scope in ("external", "internal"):
                try:
                    r = subprocess.run(
                        ["diskutil", "list", "-plist", scope],
                        capture_output=True, timeout=10,
                    )
                    if r.returncode != 0 or not r.stdout:
                        continue
                    plist = plistlib.loads(r.stdout)
                    all_disks = plist.get("AllDisksAndPartitions", [])
                    all_names = plist.get("AllDisks", [])

                    for disk_name in all_names:
                        try:
                            ir = subprocess.run(
                                ["diskutil", "info", "-plist", disk_name],
                                capture_output=True, timeout=10,
                            )
                            if ir.returncode != 0:
                                continue
                            info = plistlib.loads(ir.stdout)
                            mp = info.get("MountPoint", "")

                            # Skip boot volume (already added)
                            if mp == "/":
                                continue

                            dtype, bus = _detect_type(info)
                            is_mounted = bool(mp)
                            is_removable = (scope == "external") or info.get("Removable", False)

                            if is_mounted:
                                try:
                                    st = os.statvfs(mp)
                                    free = st.f_bfree * st.f_frsize
                                except OSError:
                                    free = 0
                            else:
                                free = 0

                            total_size = info.get("TotalSize", 0) or info.get("Size", 0)
                            if total_size == 0 and not is_mounted:
                                # Skip empty/container entries
                                continue

                            # Skip container disks (APFS containers etc.)
                            content = info.get("Content", "")
                            if "Container" in content and not is_mounted:
                                continue

                            drives.append(DriveInfo(
                                device_path=f"/dev/r{disk_name}",
                                mount_point=mp,
                                label=(info.get("VolumeName", "")
                                       or info.get("MediaName", "") or disk_name),
                                filesystem=info.get("FilesystemType", "") or
                                           info.get("Content", "Unknown"),
                                total_size=total_size,
                                free_size=free,
                                is_removable=is_removable,
                                drive_type=dtype,
                                is_mounted=is_mounted,
                                bus_protocol=bus,
                            ))
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            # Fallback: scan /Volumes
            vols = Path("/Volumes")
            if vols.exists():
                for vol in vols.iterdir():
                    if vol.name.startswith("."):
                        continue
                    try:
                        st = os.statvfs(str(vol))
                        drives.append(DriveInfo(
                            device_path=str(vol),
                            mount_point=str(vol),
                            label=vol.name,
                            filesystem="Unknown",
                            total_size=st.f_blocks * st.f_frsize,
                            free_size=st.f_bfree * st.f_frsize,
                            is_removable=True,
                            drive_type="Unknown",
                        ))
                    except OSError:
                        continue

        return drives

    @staticmethod
    def _list_linux() -> list[DriveInfo]:
        drives: list[DriveInfo] = []

        def _linux_drive_type(name: str) -> tuple[str, str]:
            """Detect drive type using sysfs. Returns (drive_type, bus)."""
            # Get base device name (strip partition number)
            base = name.rstrip("0123456789p")
            if not base:
                base = name

            try:
                # Check rotational flag
                rot_path = f"/sys/block/{base}/queue/rotational"
                if os.path.exists(rot_path):
                    with open(rot_path) as f:
                        is_rotational = f.read().strip() == "1"
                else:
                    is_rotational = True  # default

                # Check removable
                rm_path = f"/sys/block/{base}/removable"
                is_removable = False
                if os.path.exists(rm_path):
                    with open(rm_path) as f:
                        is_removable = f.read().strip() == "1"

                # Check for NVMe
                if name.startswith("nvme"):
                    return "NVMe SSD", "NVMe"

                # Check for mmcblk (SD cards, eMMC)
                if name.startswith("mmcblk"):
                    # Distinguish SD vs eMMC
                    type_path = f"/sys/block/{base}/device/type"
                    if os.path.exists(type_path):
                        with open(type_path) as f:
                            dev_type = f.read().strip()
                        if dev_type == "SD":
                            return "SD Card", "SD"
                        elif dev_type == "MMC":
                            return "eMMC", "MMC"
                    return "SD Card", "MMC"

                # Check for USB
                dev_path = f"/sys/block/{base}/device"
                if os.path.exists(dev_path):
                    real = os.path.realpath(dev_path)
                    if "/usb" in real:
                        if not is_rotational:
                            return "External SSD (USB)", "USB"
                        return "USB Drive", "USB"

                # Check for virtual disk (virtio, xvd)
                if name.startswith("vd") or name.startswith("xvd"):
                    return "Virtual", "VirtIO"

                # Check for CD/DVD
                if name.startswith("sr") or name.startswith("cd"):
                    return "Optical", "SATA"

                # Check for loop device (disk images)
                if name.startswith("loop"):
                    return "Disk Image", "Loop"

                if is_removable:
                    return "USB Drive", "USB"
                elif is_rotational:
                    return "HDD", "SATA"
                else:
                    return "SSD", "SATA"

            except Exception:
                return "Unknown", ""

        try:
            import json as _json
            # Include unmounted partitions with -a flag
            r = subprocess.run(
                ["lsblk", "-Jbno",
                 "NAME,SIZE,MOUNTPOINT,FSTYPE,LABEL,RM,TYPE,MODEL,TRAN"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                data = _json.loads(r.stdout)
                for dev in data.get("blockdevices", []):
                    # Process device and its children (partitions)
                    devices_to_check = [dev]
                    children = dev.get("children", [])
                    if children:
                        devices_to_check.extend(children)

                    for d in devices_to_check:
                        mp = d.get("mountpoint", "")
                        dev_type = d.get("type", "")
                        name = d.get("name", "")

                        # Skip whole-disk entries with partitions
                        if dev_type == "disk" and children:
                            continue
                        # Skip swap and special mounts
                        if mp in ("[SWAP]", ""):
                            is_mounted = False
                        else:
                            is_mounted = True

                        fstype = d.get("fstype") or ""
                        size = int(d.get("size", 0))
                        if size == 0:
                            continue

                        dtype, bus = _linux_drive_type(name)
                        # Override with lsblk transport info
                        tran = d.get("tran", "") or dev.get("tran", "")
                        if tran:
                            bus = tran.upper()

                        if is_mounted:
                            try:
                                st = os.statvfs(mp)
                                free = st.f_bfree * st.f_frsize
                            except OSError:
                                free = 0
                        else:
                            free = 0

                        drives.append(DriveInfo(
                            device_path=f"/dev/{name}",
                            mount_point=mp if is_mounted else "",
                            label=d.get("label") or dev.get("model", "") or "",
                            filesystem=fstype or "Unknown",
                            total_size=size,
                            free_size=free,
                            is_removable=d.get("rm") == "1" or dev.get("rm") == "1",
                            drive_type=dtype,
                            is_mounted=is_mounted,
                            bus_protocol=bus,
                        ))
        except Exception:
            pass
        return drives

    @staticmethod
    def _list_windows() -> list[DriveInfo]:
        drives: list[DriveInfo] = []

        # Map disk numbers to their media type (SSD/HDD)
        disk_types: dict[int, str] = {}
        try:
            import json as _json
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-Disk | Select Number,MediaType,BusType,Model,Size"
                 " | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                disks = _json.loads(r.stdout)
                if isinstance(disks, dict):
                    disks = [disks]
                for d in disks:
                    num = d.get("Number", -1)
                    media = d.get("MediaType", 0)
                    bus = d.get("BusType", "")
                    # MediaType: 3=HDD, 4=SSD, 5=SCM
                    bus_str = str(bus)
                    if media == 4 or media == 5:
                        if "NVMe" in bus_str:
                            dtype = "NVMe SSD"
                        elif "USB" in bus_str:
                            dtype = "External SSD (USB)"
                        elif "Thunderbolt" in bus_str:
                            dtype = "External SSD (Thunderbolt)"
                        elif "1394" in bus_str or "FireWire" in bus_str:
                            dtype = "External SSD (FireWire)"
                        else:
                            dtype = "SSD"
                    elif media == 3:
                        dtype = "HDD"
                    elif bus_str == "USB":
                        dtype = "USB Drive"
                    elif bus_str == "SD":
                        dtype = "SD Card"
                    else:
                        dtype = "Unknown"
                    disk_types[num] = dtype
        except Exception:
            pass

        # Get volumes with drive letters
        try:
            import json as _json
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-Volume | Select DriveLetter,FileSystemLabel,"
                 "FileSystem,Size,SizeRemaining,DriveType | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                vols = _json.loads(r.stdout)
                if isinstance(vols, dict):
                    vols = [vols]
                for v in vols:
                    letter = v.get("DriveLetter")
                    if not letter:
                        continue
                    vol_drive_type = v.get("DriveType", 0)
                    # DriveType: 0=Unknown, 2=Removable, 3=Fixed, 4=Network, 5=CDROM
                    if vol_drive_type == 5:
                        dtype = "Optical"
                        bus = "SATA"
                    elif vol_drive_type == 2:
                        dtype = "USB Drive"
                        bus = "USB"
                    elif vol_drive_type == 4:
                        continue  # Skip network drives
                    else:
                        # Try to match to physical disk type
                        dtype = "Unknown"
                        bus = ""
                        try:
                            pr = subprocess.run(
                                ["powershell", "-Command",
                                 f"(Get-Partition -DriveLetter {letter}"
                                 f" | Get-Disk).Number"],
                                capture_output=True, text=True, timeout=10,
                            )
                            if pr.returncode == 0 and pr.stdout.strip():
                                disk_num = int(pr.stdout.strip())
                                dtype = disk_types.get(disk_num, "Unknown")
                        except Exception:
                            pass

                    drives.append(DriveInfo(
                        device_path=f"\\\\.\\{letter}:",
                        mount_point=f"{letter}:\\",
                        label=v.get("FileSystemLabel") or "",
                        filesystem=v.get("FileSystem") or "Unknown",
                        total_size=int(v.get("Size") or 0),
                        free_size=int(v.get("SizeRemaining") or 0),
                        is_removable=(vol_drive_type == 2),
                        drive_type=dtype,
                        bus_protocol=bus,
                    ))
        except Exception:
            pass

        # Also find RAW/unformatted partitions without drive letters
        try:
            import json as _json
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-Partition | Where {-not $_.DriveLetter} "
                 "| Select DiskNumber,PartitionNumber,Size,Type,GptType"
                 " | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                parts = _json.loads(r.stdout)
                if isinstance(parts, dict):
                    parts = [parts]
                for p in parts:
                    ptype = p.get("Type", "")
                    size = int(p.get("Size", 0))
                    # Skip system partitions and tiny partitions
                    if size < 100 * 1024 * 1024:  # < 100MB
                        continue
                    if "System" in str(ptype) or "Reserved" in str(ptype):
                        continue
                    disk_num = p.get("DiskNumber", 0)
                    part_num = p.get("PartitionNumber", 0)
                    dtype = disk_types.get(disk_num, "Unknown")
                    drives.append(DriveInfo(
                        device_path=f"\\\\.\\PhysicalDrive{disk_num}",
                        mount_point="",
                        label=f"Disk {disk_num} Part {part_num} (No Letter)",
                        filesystem="RAW",
                        total_size=size,
                        free_size=0,
                        is_removable=False,
                        drive_type=dtype,
                        is_mounted=False,
                    ))
        except Exception:
            pass

        return drives


# ─────────────────────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────────────────────

def _human_size(nbytes: int) -> str:
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
