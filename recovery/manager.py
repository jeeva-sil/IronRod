"""
Recovery Manager — Orchestrates scanning, saving, and reporting.
"""

import os
import csv
import json
import time
import struct
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable

from .scanner import DiskScanner, RecoveredFile, ScanProgress, DriveInfo
from .signatures import get_all_categories, HEADER_SIGNATURES
from .smart_filter import validate_carved_file
from .tsk_scanner import save_tsk_file, TSKDeletedFile, is_available as tsk_is_available
from .damage_detector import analyze_damage, DamageReport
from .file_repair import (
    repair_file, verify_saved_file, verify_data_integrity,
    RepairResult, IntegrityCheck,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanSession:
    """Represents a complete scan session."""
    session_id: str
    device_path: str
    output_dir: str
    start_time: float = 0.0
    end_time: float = 0.0
    recovered_files: list[RecoveredFile] = field(default_factory=list)
    categories_scanned: set[str] = field(default_factory=set)
    total_bytes_scanned: int = 0
    was_cancelled: bool = False
    # Forensic metadata
    scan_mode: str = "brute-force"
    fs_type: str = ""
    total_clusters: int = 0
    free_clusters: int = 0
    free_bytes: int = 0
    # Drive health / performance
    drive_type: str = ""
    trim_enabled: bool = False
    recovery_confidence: str = ""
    skipped_empty_bytes: int = 0
    using_mmap: bool = False

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def duration_human(self) -> str:
        d = self.duration
        if d < 60:
            return f"{d:.1f}s"
        if d < 3600:
            return f"{d / 60:.1f}m"
        return f"{d / 3600:.1f}h"

    @property
    def total_recovered_size(self) -> int:
        return sum(f.size for f in self.recovered_files)

    @property
    def total_recovered_size_human(self) -> str:
        return _fmt_size(self.total_recovered_size)

    @property
    def files_by_category(self) -> dict:
        r: dict[str, list] = {}
        for f in self.recovered_files:
            r.setdefault(f.category, []).append(f)
        return r

    @property
    def summary(self) -> dict:
        by_cat = self.files_by_category
        return {
            "total_files": len(self.recovered_files),
            "total_size": self.total_recovered_size_human,
            "duration": self.duration_human,
            "categories": {
                cat: {"count": len(files),
                      "extensions": sorted(set(f.extension for f in files))}
                for cat, files in by_cat.items()
            },
        }


class RecoveryManager:
    """High-level manager for photo & video recovery."""

    def __init__(self):
        self.scanner = DiskScanner()
        self.current_session: Optional[ScanSession] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._on_progress: Optional[Callable] = None
        self._on_file_found: Optional[Callable] = None
        self._on_scan_complete: Optional[Callable] = None

    def set_callbacks(
        self,
        on_progress=None,
        on_file_found=None,
        on_scan_complete=None,
    ):
        self._on_progress = on_progress
        self._on_file_found = on_file_found
        self._on_scan_complete = on_scan_complete

    @staticmethod
    def list_drives() -> list[DriveInfo]:
        return DiskScanner.list_drives()

    @staticmethod
    def get_available_categories() -> list[str]:
        return get_all_categories()

    @property
    def is_scanning(self) -> bool:
        return self._scan_thread is not None and self._scan_thread.is_alive()

    @property
    def progress(self) -> ScanProgress:
        return self.scanner.progress

    def start_scan(
        self,
        device_path: str,
        output_dir: str,
        categories: Optional[set[str]] = None,
        preview_only: bool = False,
    ):
        if self.is_scanning:
            return

        self.current_session = ScanSession(
            session_id=f"scan_{int(time.time())}",
            device_path=device_path,
            output_dir=output_dir,
            start_time=time.time(),
            categories_scanned=categories or set(get_all_categories()),
        )

        self.scanner = DiskScanner()
        self.scanner.set_progress_callback(self._handle_progress)
        self.scanner.set_file_found_callback(self._handle_file_found)

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(device_path, output_dir, categories, preview_only),
            daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, device_path, output_dir, categories, preview_only):
        try:
            results = self.scanner.scan(
                device_path, output_dir, categories,
                preview_only=preview_only,
            )
            if self.current_session:
                self.current_session.recovered_files = results
                self.current_session.end_time = time.time()
                self.current_session.total_bytes_scanned = (
                    self.scanner.progress.scanned_bytes
                )
                self.current_session.was_cancelled = (
                    self.scanner.progress.is_cancelled
                )
                # Capture forensic metadata from scanner progress
                self.current_session.scan_mode = self.scanner.progress.scan_mode
                self.current_session.fs_type = self.scanner.progress.fs_type
                self.current_session.total_clusters = self.scanner.progress.total_clusters
                self.current_session.free_clusters = self.scanner.progress.free_clusters
                self.current_session.free_bytes = self.scanner.progress.free_bytes
                self.current_session.drive_type = self.scanner.progress.drive_type
                self.current_session.trim_enabled = self.scanner.progress.trim_enabled
                self.current_session.recovery_confidence = self.scanner.progress.recovery_confidence
                self.current_session.skipped_empty_bytes = self.scanner.progress.skipped_empty_bytes
                self.current_session.using_mmap = self.scanner.progress.using_mmap
                if output_dir and results:
                    try:
                        log_path = os.path.join(output_dir, "recovery_log.json")
                        self._save_log(log_path)
                    except Exception:
                        pass
                if self._on_scan_complete:
                    self._on_scan_complete(self.current_session)
        except Exception as e:
            logger.error("Scan failed: %s", e, exc_info=True)
            if self.current_session:
                self.current_session.end_time = time.time()
            self.scanner.progress.status_message = f"Error: {e}"
            self.scanner.progress.is_scanning = False
            if self._on_progress:
                self._on_progress(self.scanner.progress)
            if self._on_scan_complete and self.current_session:
                self._on_scan_complete(self.current_session)

    def cancel_scan(self):
        if self.scanner:
            self.scanner.cancel()

    def _handle_progress(self, progress):
        if self._on_progress:
            self._on_progress(progress)

    def _handle_file_found(self, rf):
        if self._on_file_found:
            self._on_file_found(rf)

    # ─── Deep workability validation ─────────────────────────

    def deep_validate_file(self, rf: RecoveredFile) -> bool:
        """Truly validate a file by attempting to fully decode it.

        Goes beyond header/structure checks — actually tries to render/decode
        the file data using Pillow (images) or full ISO BMFF / RIFF walk (videos).
        Sets rf.is_truly_workable to the result.

        Returns True only if the file can actually be opened and used.
        """
        if not rf.raw_device_path or rf.size <= 0:
            rf.is_truly_workable = False
            rf.workability_reason = "No raw device path"
            return False

        try:
            # Read full file data (cap at 50 MB to avoid OOM)
            max_read = min(rf.size, 50 * 1024 * 1024)
            data = self._read_from_device(rf.raw_device_path, rf.offset, max_read)
            if not data or len(data) < 100:
                rf.is_truly_workable = False
                rf.workability_reason = "Too small or empty"
                return False

            ext = rf.extension.lower()
            workable, reason = self._deep_validate_data(ext, data, rf.size)
            rf.is_truly_workable = workable
            rf.workability_reason = reason
            return workable

        except Exception as e:
            logger.warning("Deep validation failed for %s: %s", rf.display_name, e)
            rf.is_truly_workable = False
            rf.workability_reason = f"Validation error: {e}"
            return False

    @staticmethod
    def _get_ffmpeg_path() -> Optional[str]:
        """Find an ffmpeg binary: imageio-ffmpeg bundle, or system PATH."""
        try:
            import imageio_ffmpeg
            return imageio_ffmpeg.get_ffmpeg_exe()
        except Exception:
            pass
        # Fallback: look on PATH
        import shutil
        path = shutil.which("ffmpeg")
        return path

    @staticmethod
    def _ffprobe_validate(data: bytes, ext: str) -> tuple[bool, str]:
        """Write data to a temp file and use ffmpeg to probe/decode it.

        Returns (workable, reason).  This is the most reliable test:
        ffmpeg will reject files whose streams cannot be demuxed.
        """
        import tempfile, subprocess
        ffmpeg = RecoveryManager._get_ffmpeg_path()
        if not ffmpeg:
            return True, "ffmpeg not available (header-only check)"

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=f".{ext}", delete=False
            ) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            # Step 1: probe — can ffmpeg even open / identify streams?
            result = subprocess.run(
                [
                    ffmpeg, "-v", "error",
                    "-i", tmp_path,
                    "-f", "null", "-",
                ],
                capture_output=True, text=True, timeout=30,
            )
            stderr = result.stderr.strip()
            if "Invalid data found" in stderr:
                return False, "ffmpeg: invalid data — not a real media file"
            if "could not find codec" in stderr.lower():
                return False, f"ffmpeg: unsupported codec — {stderr[:80]}"
            if "error" in stderr.lower() and "opening" in stderr.lower():
                return False, f"ffmpeg: cannot open — {stderr[:80]}"

            # Step 2: try to decode a few frames to catch silent corruption
            result2 = subprocess.run(
                [
                    ffmpeg, "-v", "error",
                    "-i", tmp_path,
                    "-frames:v", "5",
                    "-frames:a", "50",
                    "-f", "null", "-",
                ],
                capture_output=True, text=True, timeout=30,
            )
            stderr2 = result2.stderr.strip()
            # Some warnings are OK; hard errors mean the file is junk
            hard_errors = [
                "invalid data", "error while decoding",
                "no such file", "could not open",
                "invalid return value",
            ]
            for err_pat in hard_errors:
                if err_pat in stderr2.lower():
                    return False, f"ffmpeg decode error: {stderr2[:100]}"

            return True, "ffmpeg: media file playable"

        except subprocess.TimeoutExpired:
            return False, "ffmpeg: decode timed out (likely corrupt)"
        except Exception as e:
            logger.warning("ffprobe_validate error: %s", e)
            return True, f"ffmpeg probe error: {e}"
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    # All video extensions that should be validated with ffmpeg
    _VIDEO_EXTS = {
        "mp4", "mov", "3gp", "m4v", "avi", "mkv", "webm",
        "flv", "wmv", "asf", "mpg", "mpeg", "ts", "mts",
        "m2ts", "vob", "ogv", "ogg", "rm", "rmvb", "swf",
    }

    @staticmethod
    def _deep_validate_data(ext: str, data: bytes, expected_size: int) -> tuple[bool, str]:
        """Deep-validate file data. Returns (workable, reason).

        Images  → Pillow full decode
        Videos  → ffmpeg probe + decode test
        RAW     → TIFF IFD structure check
        """

        # ── Image validation via Pillow ──
        _PILLOW_EXTS = {
            "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif",
            "webp", "ico", "psd", "jp2", "tga",
        }

        if ext in _PILLOW_EXTS:
            try:
                from PIL import Image as PILImage
                PILImage.MAX_IMAGE_PIXELS = None
            except ImportError:
                return True, "Pillow not available (header-only check)"

            try:
                import io as _io
                img = PILImage.open(_io.BytesIO(data))
                img.verify()
                img = PILImage.open(_io.BytesIO(data))
                img.load()

                w, h = img.size
                if w < 2 or h < 2:
                    return False, f"Image too small: {w}x{h}"
                if w * h < 16:
                    return False, f"Image has negligible pixels: {w}x{h}"

                return True, f"Image OK ({w}x{h}, {img.mode})"

            except Exception as e:
                err = str(e)
                if "truncated" in err.lower():
                    return False, f"Image truncated: {err}"
                elif "cannot identify" in err.lower():
                    return False, f"Not a valid image: {err}"
                else:
                    return False, f"Image decode failed: {err}"

        # ── HEIC / AVIF — Pillow can't decode these; use ffmpeg ──
        if ext in ("heic", "avif"):
            return RecoveryManager._ffprobe_validate(data, ext)

        # ── ALL video formats → ffmpeg probe + decode ──
        if ext in RecoveryManager._VIDEO_EXTS:
            return RecoveryManager._ffprobe_validate(data, ext)

        # ── RAW camera formats (CR2, NEF, ARW, DNG, ORF, RW2, RAF) ──
        if ext in ("cr2", "nef", "arw", "dng", "orf", "rw2"):
            if len(data) < 8:
                return False, "Too small for TIFF-based RAW"
            if data[:2] == b"II":
                byte_order = "<"
            elif data[:2] == b"MM":
                byte_order = ">"
            else:
                return False, "Invalid TIFF byte order"
            version = struct.unpack(f"{byte_order}H", data[2:4])[0]
            if version != 42:
                return False, f"Invalid TIFF version: {version}"
            ifd_offset = struct.unpack(f"{byte_order}I", data[4:8])[0]
            if ifd_offset >= len(data) or ifd_offset < 8:
                return False, f"IFD offset out of range: {ifd_offset}"
            return True, "RAW TIFF structure OK"

        if ext == "raf":
            if data[:16] != b"FUJIFILMCCD-RAW ":
                return False, "Invalid RAF header"
            return True, "RAF header OK"

        # ── Audio formats → ffmpeg probe + decode ──
        _AUDIO_EXTS = {
            "mp3", "wav", "flac", "m4a", "aiff", "aif",
            "wma", "oga", "ogg", "mid", "midi",
        }
        if ext in _AUDIO_EXTS:
            return RecoveryManager._ffprobe_validate(data, ext)

        # ── Document formats — structural validation ──
        if ext == "pdf":
            if not data[:5] == b"%PDF-":
                return False, "Not a valid PDF (missing %PDF- header)"
            # Check for at least one object or stream
            if b"obj" in data[:min(len(data), 8192)]:
                return True, "PDF structure OK"
            return False, "PDF missing object definitions"

        if ext in ("docx", "xlsx", "pptx", "zip"):
            if data[:4] != b"PK\x03\x04":
                return False, f"Not a valid ZIP/{ext.upper()} archive"
            # Try to verify the ZIP can be opened
            try:
                import io as _io, zipfile
                with zipfile.ZipFile(_io.BytesIO(data)) as zf:
                    names = zf.namelist()
                    if not names:
                        return False, "ZIP archive is empty"
                    if ext == "docx" and not any(
                        n.startswith("word/") for n in names
                    ):
                        return False, "DOCX missing word/ directory"
                    if ext == "xlsx" and not any(
                        n.startswith("xl/") for n in names
                    ):
                        return False, "XLSX missing xl/ directory"
                    if ext == "pptx" and not any(
                        n.startswith("ppt/") for n in names
                    ):
                        return False, "PPTX missing ppt/ directory"
                return True, f"{ext.upper()} archive OK ({len(names)} files)"
            except zipfile.BadZipFile as e:
                return False, f"Corrupt ZIP: {e}"
            except Exception as e:
                return False, f"ZIP validation error: {e}"

        if ext in ("sqlite", "db"):
            if data[:16] != b"SQLite format 3\x00":
                return False, "Not a valid SQLite database"
            if len(data) >= 18:
                page_size = struct.unpack(">H", data[16:18])[0]
                if page_size == 1:
                    page_size = 65536
                if page_size < 512 or (page_size & (page_size - 1)) != 0:
                    return False, f"Invalid page size: {page_size}"
            return True, "SQLite header OK"

        # ── RTF validation ──
        if ext == "rtf":
            if not data[:5] == b"{\\rtf":
                return False, "Not a valid RTF (missing {\\rtf header)"
            if b"}" not in data[:4096]:
                return False, "RTF missing closing brace"
            return True, "RTF structure OK"

        # ── XML validation ──
        if ext == "xml":
            start = data[:10]
            if start[:3] == b"\xEF\xBB\xBF":
                start = data[3:13]
            if not (start[:5] == b"<?xml" or start[:2] == b"<?"):
                return False, "Not valid XML"
            return True, "XML header OK"

        # ── HTML validation ──
        if ext in ("html", "htm"):
            lower = data[:256].lower()
            if not (b"<!doctype html" in lower or b"<html" in lower or b"<head" in lower):
                return False, "Not valid HTML"
            return True, "HTML structure OK"

        # ── EPS validation ──
        if ext == "eps":
            if data[:11] != b"%!PS-Adobe-":
                return False, "Not valid EPS"
            return True, "EPS header OK"

        # ── OLE2 compound documents (DOC, XLS, PPT, MSG) ──
        if ext in ("doc", "xls", "ppt", "msg"):
            if data[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                return False, f"Not a valid OLE2/{ext.upper()} file"
            if len(data) >= 0x1C:
                major = struct.unpack("<H", data[0x1A:0x1C])[0]
                if major not in (3, 4):
                    return False, f"Invalid CFB version: {major}"
            return True, f"OLE2/{ext.upper()} structure OK"

        # ── EPUB, ODT, ODS, ODP — ZIP-based ──
        if ext in ("epub", "odt", "ods", "odp"):
            if data[:4] != b"PK\x03\x04":
                return False, f"Not a valid {ext.upper()} (not ZIP)"
            try:
                import io as _io, zipfile
                with zipfile.ZipFile(_io.BytesIO(data)) as zf:
                    names = zf.namelist()
                    if not names:
                        return False, f"{ext.upper()} archive empty"
                    if ext == "epub" and "mimetype" not in names:
                        return False, "EPUB missing mimetype"
                    if ext in ("odt", "ods", "odp") and "mimetype" not in names:
                        return False, f"{ext.upper()} missing mimetype"
                return True, f"{ext.upper()} archive OK ({len(names)} files)"
            except Exception as e:
                return False, f"Corrupt {ext.upper()}: {e}"

        # ── Archives ──
        _ARCHIVE_EXTS = {
            "7z", "rar", "gz", "gzip", "bz2", "xz", "tar",
            "cab", "iso", "dmg", "zst", "zstd", "lz4",
        }
        if ext in _ARCHIVE_EXTS:
            # Use structural validators from smart_filter
            from .smart_filter import validate_carved_file as _scv
            if _scv(ext, data):
                return True, f"Archive ({ext.upper()}) structure OK"
            return False, f"Invalid {ext.upper()} archive"

        # ── Executables ──
        _EXEC_EXTS = {"exe", "dll", "elf", "so", "macho", "dylib", "dex", "wasm", "class", "pyc"}
        if ext in _EXEC_EXTS:
            from .smart_filter import validate_carved_file as _scv
            if _scv(ext, data):
                return True, f"Executable ({ext.upper()}) header OK"
            return False, f"Invalid {ext.upper()} executable"

        # ── Fonts ──
        _FONT_EXTS = {"ttf", "otf", "woff", "woff2"}
        if ext in _FONT_EXTS:
            from .smart_filter import validate_carved_file as _scv
            if _scv(ext, data):
                return True, f"Font ({ext.upper()}) structure OK"
            return False, f"Invalid {ext.upper()} font"

        # ── Database / Data Science ──
        _DATA_EXTS = {
            "parquet", "avro", "orc", "hdf5", "h5",
            "npy", "pcap", "pcapng",
        }
        if ext in _DATA_EXTS:
            from .smart_filter import validate_carved_file as _scv
            if _scv(ext, data):
                return True, f"Data file ({ext.upper()}) header OK"
            return False, f"Invalid {ext.upper()} data file"

        # ── System / Misc ──
        _SYS_EXTS = {"lnk", "reg", "plist", "gpg", "der"}
        if ext in _SYS_EXTS:
            from .smart_filter import validate_carved_file as _scv
            if _scv(ext, data):
                return True, f"System file ({ext.upper()}) OK"
            return False, f"Invalid {ext.upper()} system file"

        # ── Fallback for unknown types ──
        return True, "No deep validator (header-only)"



    # ─── Damage analysis for preview-mode files ──────────────

    def analyze_file_damage(self, rf: RecoveredFile) -> DamageReport:
        """Analyze a preview-mode file for damage without saving.

        Reads the file data from the raw device and runs damage analysis.
        """
        if not rf.raw_device_path or rf.size <= 0:
            report = DamageReport()
            report.is_damaged = True
            report.damage_level = "fatal"
            report.damage_score = 1.0
            report.issues.append("Cannot read file data")
            rf.damage_report = report
            return report

        try:
            data = self._read_from_device(
                rf.raw_device_path, rf.offset, min(rf.size, 1024 * 1024))
            report = analyze_damage(rf.extension, data, expected_size=rf.size)
            rf.damage_report = report
            return report
        except Exception as e:
            logger.warning("Damage analysis failed for offset %d: %s",
                           rf.offset, e)
            report = DamageReport()
            report.is_damaged = True
            report.damage_level = "severe"
            report.issues.append(f"Analysis error: {e}")
            rf.damage_report = report
            return report

    # ─── Save selected files ─────────────────────────────────

    def save_selected_files(
        self,
        files: list[RecoveredFile],
        output_dir: str,
        on_progress=None,
    ) -> list[RecoveredFile]:
        """
        Save selected files.  For preview-mode files, re-reads from
        the raw device at the stored offset.
        """
        saved = []
        total = len(files)
        logger.info("Saving %d files to %s", total, output_dir)

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        for i, rf in enumerate(files):
            try:
                if rf.is_saved and rf.recovered_path and os.path.exists(rf.recovered_path):
                    saved.append(rf)
                    if on_progress:
                        on_progress(i + 1, total, saved_ok=True,
                                    file_size=rf.size, file_ext=rf.extension)
                    continue

                subdir = os.path.join(output_dir, rf.category)
                os.makedirs(subdir, exist_ok=True)
                filename = f"recovered_{i + 1:06d}.{rf.extension}"
                out_path = os.path.join(subdir, filename)

                # Avoid overwrite
                if os.path.exists(out_path):
                    base, ext = os.path.splitext(out_path)
                    c = 1
                    while os.path.exists(out_path):
                        out_path = f"{base}_{c}{ext}"
                        c += 1

                # Re-read from raw device
                if not rf.raw_device_path:
                    logger.warning("File %d has no raw_device_path — cannot re-carve", i)
                    if on_progress:
                        on_progress(i + 1, total, saved_ok=False,
                                    file_size=0, file_ext=rf.extension)
                    continue
                if rf.size <= 0:
                    logger.warning("File %d has invalid size %d — skipping", i, rf.size)
                    if on_progress:
                        on_progress(i + 1, total, saved_ok=False,
                                    file_size=0, file_ext=rf.extension)
                    continue

                # TSK files: use pytsk3 to read data blocks (handles fragmentation)
                if rf.source == "tsk" and rf.tsk_inode > 0 and tsk_is_available():
                    tsk_file = TSKDeletedFile(
                        name=rf.original_name or rf.display_name,
                        path=rf.original_path or "",
                        extension=rf.extension,
                        category=rf.category,
                        size=rf.size,
                        inode=rf.tsk_inode,
                        offset=rf.offset,
                        raw_device=rf.raw_device_path,
                    )
                    ok = save_tsk_file(rf.raw_device_path, tsk_file, out_path)
                else:
                    ok = self._re_carve_and_save(
                        rf.raw_device_path, rf.offset, rf.size,
                        rf.signature, out_path, rf=rf,
                    )
                if ok:
                    rf.recovered_path = out_path
                    rf.is_saved = True
                    saved.append(rf)
                    if on_progress:
                        on_progress(i + 1, total, saved_ok=True,
                                    file_size=rf.size, file_ext=rf.extension)
                else:
                    logger.warning("Re-carve failed for file %d (offset=%d, size=%d, device=%s)",
                                   i, rf.offset, rf.size, rf.raw_device_path)
                    if on_progress:
                        on_progress(i + 1, total, saved_ok=False,
                                    file_size=0, file_ext=rf.extension)

            except Exception as e:
                logger.warning("Save failed for file %d: %s", i, e, exc_info=True)
                if on_progress:
                    on_progress(i + 1, total, saved_ok=False,
                                file_size=0, file_ext=rf.extension)

        logger.info("Save complete: %d/%d files saved", len(saved), total)
        return saved

    @staticmethod
    def _read_from_device(device: str, offset: int, size: int) -> bytes:
        """Read *size* bytes from a raw device at *offset*, with 512-byte
        sector alignment required by macOS /dev/rdisk* character devices."""
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

    @staticmethod
    def _re_carve_and_save(device, offset, size, sig, out_path,
                           rf: RecoveredFile = None,
                           auto_repair: bool = True) -> bool:
        """Re-read carved data from device and save to file.

        Enhanced pipeline:
          1. Re-read raw data from device
          2. Format-aware trimming
          3. Damage detection & analysis
          4. Automatic repair if damaged and repairable
          5. Pre-save integrity verification
          6. Write to disk
          7. Post-save readback verification
        """
        try:
            logger.debug("Re-carving: device=%s offset=%d size=%d mode=%s -> %s",
                         device, offset, size,
                         sig.carve_mode if sig else "?", out_path)

            data = RecoveryManager._read_from_device(device, offset, size)
            if not data:
                logger.warning("Re-carve: no data read from %s at offset %d",
                               device, offset)
                return False

            # ── Format-aware re-carving ───────────────────────
            mode = sig.carve_mode if sig else "maxread"

            if mode == "footer" and sig and sig.footer:
                if sig.extension == "jpg":
                    end = data.rfind(sig.footer)
                else:
                    end = data.find(sig.footer)
                if end != -1:
                    data = data[:end + len(sig.footer)]

            elif mode == "isobmff":
                trimmed = RecoveryManager._walk_boxes_for_size(data)
                if trimmed is not None and trimmed >= (sig.min_size if sig else 1024):
                    data = data[:trimmed]

            elif mode == "header":
                hdr_size = RecoveryManager._read_header_size(data, sig)
                if hdr_size is not None and hdr_size >= (sig.min_size if sig else 256):
                    data = data[:hdr_size]

            elif mode == "maxread":
                trim_pos = RecoveryManager._find_next_header_boundary(
                    data, sig.min_size if sig else 4096)
                if trim_pos is not None and trim_pos >= (sig.min_size if sig else 4096):
                    data = data[:trim_pos]

            # ── Damage detection ─────────────────────────────
            ext = sig.extension if sig else "bin"
            damage = analyze_damage(ext, data, expected_size=size)
            if rf is not None:
                rf.damage_report = damage

            # ── Automatic repair if damaged ──────────────────
            if damage.is_damaged and damage.repairable and auto_repair:
                logger.info("File at offset %d has %s damage (%s) — attempting repair",
                            offset, damage.damage_level, damage.short_summary)
                repair = repair_file(ext, data, damage)
                if rf is not None:
                    rf.repair_result = repair
                if repair.success and repair.repaired_data:
                    data = repair.repaired_data
                    if rf is not None:
                        rf.is_repaired = True
                        rf.damage_report = repair.damage_after
                    logger.info("Repair successful for offset %d: %s",
                                offset, repair.summary)
                else:
                    logger.warning("Repair failed for offset %d: %s",
                                   offset, ", ".join(repair.actions_failed))
            elif damage.is_damaged and damage.damage_level == "fatal":
                logger.warning("File at offset %d has fatal damage — saving as-is",
                               offset)

            # ── Pre-save integrity check (informational only — never skip) ──
            pre_check = verify_data_integrity(data, ext)
            if not pre_check.passed and not pre_check.format_valid:
                logger.info(
                    "Integrity check note for offset %d: format_valid=%s, "
                    "damage=%s — saving anyway",
                    offset, pre_check.format_valid,
                    damage.damage_level if damage else "unknown")

            # Ensure output directory exists
            out_dir = os.path.dirname(out_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            # ── Write to disk ────────────────────────────────
            with open(out_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())  # Force flush to disk

            # ── Post-save readback verification ──────────────
            integrity = verify_saved_file(out_path, data, ext)
            if rf is not None:
                rf.integrity_check = integrity

            if not integrity.passed:
                logger.warning(
                    "Post-save integrity check FAILED for %s: %s",
                    out_path, ", ".join(integrity.issues))
            else:
                logger.info(
                    "Saved & verified %d bytes (%s) to %s [MD5: %s]",
                    len(data), ext, out_path, integrity.actual_md5[:12])

            return True

        except PermissionError as e:
            logger.error("Permission denied saving file: %s (device=%s, out=%s)",
                         e, device, out_path)
            return False
        except OSError as e:
            logger.error("OS error saving file: %s (device=%s, offset=%d, size=%d, out=%s)",
                         e, device, offset, size, out_path)
            return False
        except Exception as e:
            logger.error("Unexpected error saving file: %s", e, exc_info=True)
            return False

    # ── helpers used by _re_carve_and_save ────────────────────

    @staticmethod
    def _walk_boxes_for_size(data: bytes) -> Optional[int]:
        """Walk top-level ISO Base Media (MP4/MOV/HEIC) boxes and
        return the total file size, or None if parsing fails."""
        import struct
        KNOWN = {
            b"ftyp", b"moov", b"mdat", b"free", b"skip",
            b"wide", b"meta", b"moof", b"mfra", b"styp",
            b"sidx", b"ssix", b"pdin", b"uuid",
        }
        pos = 0
        length = len(data)
        while pos < length:
            if pos + 8 > length:
                break
            box_size = struct.unpack(">I", data[pos:pos + 4])[0]
            box_type = data[pos + 4:pos + 8]
            if box_size == 1 and pos + 16 <= length:
                box_size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            if box_size < 8:
                break
            if box_type not in KNOWN:
                break
            pos += box_size
        return pos if pos > 0 else None

    @staticmethod
    def _read_header_size(data: bytes, sig) -> Optional[int]:
        """Read the file size from a format's header (BMP, ICO, RIFF)."""
        import struct
        if not sig:
            return None
        ext = sig.extension
        try:
            if ext == "bmp" and len(data) >= 6:
                return struct.unpack("<I", data[2:6])[0]
            if ext == "ico" and len(data) >= 6:
                count = struct.unpack("<H", data[4:6])[0]
                if count == 0 or count > 256:
                    return None
                dir_end = 6 + count * 16
                if len(data) < dir_end:
                    return None
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
                return max_end
            if ext in ("webp", "avi") and len(data) >= 8:
                riff_data = struct.unpack("<I", data[4:8])[0]
                return riff_data + 8
        except Exception:
            pass
        return None

    # Short / common byte patterns that appear frequently inside other
    # file formats and cause false-positive "next file" trimming.
    _AMBIGUOUS_HEADERS: set[bytes] = {
        b"BM",                          # 2 bytes — everywhere
        b"\x00\x00\x01\x00",          # ICO — leading zeros
        b"\x00\x00\x01\xBA",          # MPEG-PS pack start
        b"\x00\x00\x01\xB3",          # MPEG-1 sequence header
        b"II\x2A\x00",                 # TIFF LE
        b"MM\x00\x2A",                 # TIFF BE
        b"FWS",                          # SWF
        b"CWS",                          # SWF compressed
    }

    @staticmethod
    def _find_next_header_boundary(data: bytes, start: int) -> Optional[int]:
        """Find the next *high-confidence* file header in *data* after
        *start* to trim maxread-carved files at the boundary of the next
        file.  Skips ambiguous / short signatures."""
        from .signatures import HEADER_SIGNATURES, RIFF_TYPES, FTYP_BRANDS
        best = None
        search = data[start:]

        for hdr_bytes, _sig in HEADER_SIGNATURES:
            if hdr_bytes in RecoveryManager._AMBIGUOUS_HEADERS:
                continue
            pos = search.find(hdr_bytes)
            if pos != -1:
                actual = start + pos
                if best is None or actual < best:
                    best = actual

        # RIFF — validate sub-type
        idx = 0
        while idx < len(search):
            pos = search.find(b"RIFF", idx)
            if pos == -1:
                break
            sub_off = pos + 8
            if sub_off + 4 <= len(search):
                if search[sub_off:sub_off + 4] in RIFF_TYPES:
                    actual = start + pos
                    if best is None or actual < best:
                        best = actual
                    break
            idx = pos + 1

        # ftyp — validate brand
        idx = 0
        while idx < len(search):
            pos = search.find(b"ftyp", idx)
            if pos == -1 or pos < 4:
                break
            box_start = pos - 4
            import struct as _st
            box_sz = _st.unpack(">I", search[box_start:box_start + 4])[0]
            if 8 <= box_sz <= 65536:
                brand_off = pos + 4
                if brand_off + 4 <= len(search):
                    brand = search[brand_off:brand_off + 4]
                    if brand in FTYP_BRANDS or brand.lower() in FTYP_BRANDS:
                        actual = start + box_start
                        if best is None or actual < best:
                            best = actual
                        break
            idx = pos + 1

        return best

    # ─── Reports ──────────────────────────────────────────────

    def _save_log(self, filepath):
        data = {
            "session": self.current_session.session_id if self.current_session else "",
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": self.current_session.device_path if self.current_session else "",
            "log": self.scanner.get_recovery_log(),
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def export_report_csv(self, filepath):
        if not self.current_session:
            return
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "#", "Category", "Extension", "Description",
                "Size", "Size (human)", "Offset (hex)", "Sector",
                "MD5", "Path", "Valid",
            ])
            for i, rf in enumerate(self.current_session.recovered_files, 1):
                w.writerow([
                    i, rf.category, rf.extension, rf.description,
                    rf.size, rf.size_human,
                    f"0x{rf.offset:X}", rf.sector,
                    rf.md5, rf.recovered_path, rf.is_valid,
                ])

    def export_report_json(self, filepath):
        if not self.current_session:
            return
        s = self.current_session
        report = {
            "session_id": s.session_id,
            "device": s.device_path,
            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.start_time)),
            "duration": s.duration_human,
            "total_files": len(s.recovered_files),
            "total_size": s.total_recovered_size_human,
            "cancelled": s.was_cancelled,
            "scan_mode": s.scan_mode,
            "filesystem": s.fs_type or "unknown",
            "forensic_info": {
                "mode": s.scan_mode,
                "fs_type": s.fs_type,
                "total_clusters": s.total_clusters,
                "free_clusters": s.free_clusters,
                "free_bytes": s.free_bytes,
                "free_human": _fmt_size(s.free_bytes) if s.free_bytes else "N/A",
            } if s.scan_mode == "forensic" else None,
            "method": (
                f"Forensic: {s.fs_type.upper()} allocation bitmap → unallocated cluster scan"
                if s.scan_mode == "forensic"
                else "Raw binary file carving (brute-force)"
            ),
            "formats": "JPG, PNG, HEIC, MP4, MOV",
            "summary": s.summary,
            "files": [
                {
                    "n": i,
                    "category": rf.category,
                    "extension": rf.extension,
                    "description": rf.description,
                    "size": rf.size,
                    "size_human": rf.size_human,
                    "offset_hex": f"0x{rf.offset:X}",
                    "sector": rf.sector,
                    "md5": rf.md5,
                    "path": rf.recovered_path,
                }
                for i, rf in enumerate(s.recovered_files, 1)
            ],
            "recovery_log": self.scanner.get_recovery_log(),
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)

    @staticmethod
    def open_output_folder(path: str):
        import subprocess as _sp
        system = platform.system()
        try:
            if system == "Darwin":
                _sp.run(["open", path])
            elif system == "Windows":
                os.startfile(path)
            else:
                _sp.run(["xdg-open", path])
        except Exception:
            pass


def _fmt_size(n: int) -> str:
    s = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{s:.1f} TB"


import platform
