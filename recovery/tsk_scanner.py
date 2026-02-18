"""
TSK Scanner — Filesystem-level deleted file recovery using The Sleuth Kit (pytsk3).

Unlike raw binary carving, this module traverses the filesystem's directory
structure and finds files whose metadata entries are marked as DELETED/UNALLOC.
These files still have their original filenames, sizes, and directory paths —
much more reliable than signature-based carving.

Supports: exFAT, FAT12/16/32, NTFS, HFS+, ext2/3/4, ISO9660, UFS.

Requires: pytsk3 (pip install pytsk3)
"""

from __future__ import annotations

import os
import time
import struct
import logging
import threading
from typing import Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import pytsk3 — gracefully degrade if not available
try:
    import pytsk3
    HAS_TSK = True
except ImportError:
    HAS_TSK = False
    logger.info("pytsk3 not installed — filesystem-level recovery disabled")


# ── Extensions by category (all 9 recovery categories) ──────

_CATEGORY_EXTS: dict[str, set[str]] = {
    "Image": {
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif",
        "webp", "jp2", "psd", "ico", "tga", "svg",
        "heic", "heif", "avif",
        "cr2", "nef", "arw", "dng", "orf", "rw2", "raf",
        "raw", "sr2", "pef", "x3f",
    },
    "Video": {
        "mp4", "mov", "avi", "mkv", "webm", "flv", "wmv",
        "mpg", "mpeg", "m4v", "3gp", "3g2",
        "ts", "mts", "m2ts", "vob",
        "ogv", "ogg", "rm", "rmvb", "swf",
        "asf", "f4v", "divx",
    },
    "Audio": {
        "mp3", "wav", "flac", "aac", "m4a", "wma", "ogg",
        "aiff", "aif", "mid", "midi", "opus", "ape", "mka",
        "ac3", "dts", "amr", "ra", "au", "snd",
    },
    "Document": {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "rtf", "txt", "csv", "xml", "html", "htm", "json",
        "odt", "ods", "odp", "epub", "pages", "numbers",
        "keynote", "tex", "md", "log", "ini", "cfg", "yaml",
        "yml", "toml", "svg", "eps", "ps",
    },
    "Archive": {
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
        "cab", "iso", "dmg", "zst", "lz4", "lzma",
        "z", "arj", "lzh", "ace", "sit",
    },
    "Executable": {
        "exe", "dll", "so", "dylib", "elf", "bin",
        "msi", "app", "deb", "rpm", "apk", "ipa",
        "jar", "class", "pyc", "wasm", "dex",
    },
    "Font": {
        "ttf", "otf", "woff", "woff2", "eot", "fon", "pfb", "pfm",
    },
    "Database": {
        "db", "sqlite", "sqlite3", "mdb", "accdb", "dbf",
        "sql", "bak", "mdf", "ldf", "frm", "ibd",
        "parquet", "hdf5", "h5", "npy", "npz",
    },
    "System": {
        "lnk", "reg", "plist", "sys", "drv", "inf",
        "dat", "tmp", "bak", "dmp", "evt", "evtx",
        "pcap", "pcapng", "vmdk", "vdi", "vhd", "qcow2",
    },
}

# Build reverse lookup: extension → category
_EXT_TO_CATEGORY: dict[str, str] = {}
for _cat, _exts in _CATEGORY_EXTS.items():
    for _ext in _exts:
        if _ext not in _EXT_TO_CATEGORY:  # first category wins on overlap
            _EXT_TO_CATEGORY[_ext] = _cat

# Flat set of all known extensions
_ALL_EXTS: set[str] = set()
for _exts in _CATEGORY_EXTS.values():
    _ALL_EXTS |= _exts

# Legacy aliases
_IMAGE_EXTS = _CATEGORY_EXTS["Image"]
_VIDEO_EXTS = _CATEGORY_EXTS["Video"]

# Maximum time for TSK scan before we give up and proceed to carving
TSK_TIMEOUT = 60  # seconds


def _ext_category(ext: str) -> str:
    """Map a file extension to its recovery category."""
    return _EXT_TO_CATEGORY.get(ext.lower(), "")


@dataclass
class TSKDeletedFile:
    """A deleted file found via filesystem directory traversal."""
    name: str               # Original filename
    path: str               # Full path in filesystem (e.g. /Photos/IMG_001.jpg)
    extension: str           # Without dot, lowercase
    category: str            # "Image" or "Video"
    size: int                # File size in bytes (from metadata)
    inode: int               # Inode / MFT entry number
    offset: int              # Byte offset on disk (computed from filesystem)
    raw_device: str          # Raw device path for reading
    deleted_time: float = 0.0  # Deletion timestamp if available


class RawDeviceImgInfo(pytsk3.Img_Info if HAS_TSK else object):
    """pytsk3 Img_Info wrapper for a raw block device or disk image.

    pytsk3.Img_Info normally takes a file path, but on macOS
    we may need to use the raw device (e.g. /dev/rdisk2s1).
    This wrapper opens the device ourselves and provides the
    read/get_size interface pytsk3 expects.
    """

    def __init__(self, device_path: str):
        self._device_path = device_path
        self._fh = open(device_path, "rb")
        # Get device size
        self._fh.seek(0, 2)
        self._size = self._fh.tell()
        self._fh.seek(0)
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_RAW)

    def close(self):
        if self._fh:
            self._fh.close()

    def read(self, offset: int, length: int) -> bytes:
        """Read from the device at a specific offset."""
        self._fh.seek(offset)
        return self._fh.read(length)

    def get_size(self) -> int:
        return self._size


def scan_deleted_files(
    device_path: str,
    want_image: bool = True,
    want_video: bool = True,
    on_file_found: Optional[Callable[[TSKDeletedFile], None]] = None,
    on_status: Optional[Callable[[str], None]] = None,
    timeout: float = TSK_TIMEOUT,
    categories: Optional[set[str]] = None,
) -> list[TSKDeletedFile]:
    """
    Scan a raw device for deleted files using TSK.

    Runs the actual filesystem traversal in a **separate thread** with a
    timeout so it never blocks the main scan pipeline.  If the timeout is
    reached, whatever files have been found so far are returned and raw
    carving can proceed immediately.

    Args:
        device_path:  Raw device path (e.g. /dev/rdisk2s1) or disk image.
        want_image:   Include deleted image files (legacy, use categories).
        want_video:   Include deleted video files (legacy, use categories).
        on_file_found: Callback for each deleted file found.
        on_status:    Callback for status messages.
        timeout:      Maximum seconds for TSK scan (default 60).
        categories:   Set of category names to recover (None = all).

    Returns:
        List of TSKDeletedFile objects found (may be partial on timeout).
    """
    if not HAS_TSK:
        logger.warning("pytsk3 not installed — skipping TSK scan")
        return []

    if on_status:
        on_status("🔍 TSK: Opening device for filesystem analysis...")

    deleted_files: list[TSKDeletedFile] = []
    cancel_event = threading.Event()
    error_holder: list[str] = []

    def _worker():
        """Runs the full TSK scan; writes results into *deleted_files*."""
        try:
            _do_tsk_scan(
                device_path, want_image, want_video,
                deleted_files, on_file_found, on_status,
                cancel_event, categories,
            )
        except Exception as exc:
            error_holder.append(str(exc))
            logger.warning("TSK worker error: %s", exc)

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout=timeout)

    if worker.is_alive():
        # TSK scan is taking too long — signal cancellation
        cancel_event.set()
        logger.info(
            "TSK: Timed out after %.0fs, proceeding with %d files found so far",
            timeout, len(deleted_files),
        )
        if on_status:
            on_status(
                f"⏱️ TSK: Timed out after {timeout:.0f}s — "
                f"found {len(deleted_files)} deleted files, "
                f"proceeding to raw carving..."
            )
        # Don't block waiting — let the daemon thread die on its own
    else:
        # Finished in time
        if error_holder:
            if on_status:
                on_status(f"⚠️ TSK: {error_holder[0]}")
        elif deleted_files:
            if on_status:
                on_status(f"✅ TSK: Found {len(deleted_files)} deleted files via filesystem analysis")
        else:
            if on_status:
                on_status("ℹ️ TSK: No deleted files found in filesystem metadata")

    logger.info("TSK: Returning %d deleted files", len(deleted_files))
    return deleted_files


def _do_tsk_scan(
    device_path: str,
    want_image: bool,
    want_video: bool,
    results: list[TSKDeletedFile],
    on_file_found: Optional[Callable],
    on_status: Optional[Callable],
    cancel: threading.Event,
    categories: Optional[set[str]] = None,
):
    """Internal TSK scan logic — runs inside a worker thread."""

    # Open the raw device
    try:
        img_info = pytsk3.Img_Info(device_path)
    except Exception:
        try:
            img_info = RawDeviceImgInfo(device_path)
        except Exception as exc:
            raise RuntimeError(f"Cannot open device {device_path}: {exc}") from exc

    if cancel.is_set():
        return

    try:
        fs_info = pytsk3.FS_Info(img_info)
    except Exception as exc:
        raise RuntimeError(f"No supported filesystem found: {exc}") from exc

    fs_type_name = _get_fs_type_name(fs_info)
    logger.info("TSK: Filesystem type: %s, block_size=%d",
                fs_type_name, fs_info.info.block_size)

    if on_status:
        on_status(f"🔍 TSK: Traversing {fs_type_name} directory tree for deleted files...")

    # Determine which extensions to look for
    wanted_exts: set[str] = set()
    if categories is not None:
        # Use the categories set — includes all 9 categories
        for cat in categories:
            wanted_exts |= _CATEGORY_EXTS.get(cat, set())
    else:
        # Legacy fallback: use want_image / want_video booleans
        if want_image:
            wanted_exts |= _IMAGE_EXTS
        if want_video:
            wanted_exts |= _VIDEO_EXTS
    # If still empty, scan everything
    if not wanted_exts:
        wanted_exts = _ALL_EXTS

    visited_inodes: set[int] = set()
    dirs_visited = [0]
    entries_scanned = [0]

    # Traverse the directory tree
    try:
        root_dir = fs_info.open_dir("/")
        _traverse_directory(
            fs_info, root_dir, "/", device_path,
            wanted_exts, results, on_file_found, on_status,
            visited_inodes, cancel, dirs_visited, entries_scanned,
            depth=0,
        )
    except Exception as exc:
        if not cancel.is_set():
            logger.warning("TSK: Directory traversal error: %s", exc)

    if cancel.is_set():
        return

    # Also try to find orphan files
    try:
        if on_status:
            on_status(f"🔍 TSK: Searching orphan files ({len(results)} found so far)...")
        _find_orphan_files(
            fs_info, device_path, wanted_exts,
            results, on_file_found, cancel,
            existing_inodes={f.inode for f in results},
        )
    except Exception as exc:
        if not cancel.is_set():
            logger.debug("TSK: Orphan file search failed: %s", exc)


def _traverse_directory(
    fs_info,
    directory,
    path: str,
    device_path: str,
    wanted_exts: set[str],
    results: list[TSKDeletedFile],
    on_file_found: Optional[Callable],
    on_status: Optional[Callable],
    visited_inodes: set[int],
    cancel: threading.Event,
    dirs_visited: list[int],
    entries_scanned: list[int],
    depth: int,
):
    """Recursively traverse directories, collecting deleted image/video files.

    Checks *cancel* event frequently so the scan can be aborted on timeout.
    """
    if depth > 64 or cancel.is_set():
        return

    try:
        for entry in directory:
            # ── Check cancellation on every entry ──
            if cancel.is_set():
                return

            entries_scanned[0] += 1

            # Periodic progress update (every 500 entries)
            if entries_scanned[0] % 500 == 0 and on_status:
                on_status(
                    f"🔍 TSK: Scanned {entries_scanned[0]:,} entries, "
                    f"{dirs_visited[0]:,} dirs — "
                    f"found {len(results)} deleted files..."
                )

            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")

                # Skip . and .. and macOS AppleDouble resource fork files
                if name in (".", "..", "$OrphanFiles"):
                    continue
                if name.startswith("._"):
                    continue

                # Get metadata
                meta = entry.info.meta
                if meta is None:
                    continue

                inode = meta.addr
                if inode in visited_inodes:
                    continue
                visited_inodes.add(inode)

                f_type = meta.type

                # Recurse into directories (including deleted ones)
                if f_type == pytsk3.TSK_FS_META_TYPE_DIR:
                    dirs_visited[0] += 1
                    try:
                        sub_dir = entry.as_directory()
                        sub_path = f"{path}{name}/" if path.endswith("/") else f"{path}/{name}/"
                        _traverse_directory(
                            fs_info, sub_dir, sub_path, device_path,
                            wanted_exts, results, on_file_found, on_status,
                            visited_inodes, cancel, dirs_visited, entries_scanned,
                            depth + 1,
                        )
                    except Exception:
                        pass
                    continue

                # Regular file — check if deleted
                if f_type != pytsk3.TSK_FS_META_TYPE_REG:
                    continue

                is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                if not is_deleted:
                    # Also check the name flags
                    name_flags = entry.info.name.flags
                    is_deleted = bool(name_flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)

                if not is_deleted:
                    continue

                # Check extension
                ext = ""
                if "." in name:
                    ext = name.rsplit(".", 1)[-1].lower()
                if ext not in wanted_exts:
                    continue

                # Get file size
                file_size = meta.size
                if file_size is None or file_size <= 0:
                    continue

                # Skip very small files (< 1KB likely corrupt)
                if file_size < 1024:
                    continue

                category = _ext_category(ext)
                if not category:
                    continue

                full_path = f"{path}{name}" if path.endswith("/") else f"{path}/{name}"

                # Try to get deletion time
                del_time = 0.0
                try:
                    if hasattr(meta, 'crtime') and meta.crtime:
                        del_time = float(meta.crtime)
                except Exception:
                    pass

                tsk_file = TSKDeletedFile(
                    name=name,
                    path=full_path,
                    extension=ext,
                    category=category,
                    size=file_size,
                    inode=inode,
                    offset=_get_file_offset(fs_info, entry, meta),
                    raw_device=device_path,
                    deleted_time=del_time,
                )
                results.append(tsk_file)

                if on_file_found:
                    on_file_found(tsk_file)

                logger.debug("TSK: Deleted file: %s (%d bytes, inode=%d)",
                             full_path, file_size, inode)

            except Exception as e:
                # Skip problematic entries
                logger.debug("TSK: Error processing entry: %s", e)
                continue

    except Exception as e:
        logger.debug("TSK: Error traversing directory %s: %s", path, e)


def _find_orphan_files(
    fs_info,
    device_path: str,
    wanted_exts: set[str],
    results: list[TSKDeletedFile],
    on_file_found: Optional[Callable],
    cancel: threading.Event,
    existing_inodes: set[int],
):
    """Try to find orphan deleted files by scanning inode/MFT tables directly."""
    if cancel.is_set():
        return

    try:
        # Try to open the orphan directory ($OrphanFiles)
        try:
            orphan_dir = fs_info.open_dir("/$OrphanFiles")
        except Exception:
            # Not all filesystems support this
            return

        for entry in orphan_dir:
            if cancel.is_set():
                return
            try:
                meta = entry.info.meta
                if meta is None:
                    continue

                inode = meta.addr
                if inode in existing_inodes:
                    continue

                if meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                    continue

                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")

                ext = ""
                if "." in name:
                    ext = name.rsplit(".", 1)[-1].lower()
                if ext not in wanted_exts:
                    continue

                file_size = meta.size
                if file_size is None or file_size <= 0 or file_size < 1024:
                    continue

                category = _ext_category(ext)
                if not category:
                    continue

                tsk_file = TSKDeletedFile(
                    name=name,
                    path=f"/$OrphanFiles/{name}",
                    extension=ext,
                    category=category,
                    size=file_size,
                    inode=inode,
                    offset=_get_file_offset(fs_info, entry, meta),
                    raw_device=device_path,
                )
                results.append(tsk_file)
                existing_inodes.add(inode)

                if on_file_found:
                    on_file_found(tsk_file)

            except Exception:
                continue

    except Exception as e:
        if not cancel.is_set():
            logger.debug("TSK: Orphan scan error: %s", e)


def _get_file_offset(fs_info, entry, meta) -> int:
    """Get the byte offset of the first data block/cluster on disk."""
    try:
        # Open the file to get its data runs
        if hasattr(entry, 'info') and hasattr(entry.info, 'name'):
            inode = meta.addr
            f = fs_info.open_meta(inode)
            # Read first byte to trigger data run resolution
            # The offset is: block_address * block_size
            for attr in f:
                if hasattr(attr, 'info') and attr.info.type in (
                    pytsk3.TSK_FS_ATTR_TYPE_DEFAULT,
                    pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
                ):
                    for run in attr:
                        if run.addr > 0:
                            return run.addr * fs_info.info.block_size
    except Exception:
        pass
    return 0


def _get_fs_type_name(fs_info) -> str:
    """Get a human-readable filesystem type name."""
    try:
        fs_type = fs_info.info.ftype
        _FS_NAMES = {
            pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
            pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
            pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
            pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
            pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
            pytsk3.TSK_FS_TYPE_HFS: "HFS+",
            pytsk3.TSK_FS_TYPE_EXT2: "ext2",
            pytsk3.TSK_FS_TYPE_EXT3: "ext3",
            pytsk3.TSK_FS_TYPE_EXT4: "ext4",
            pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
            pytsk3.TSK_FS_TYPE_FFS1: "UFS1",
            pytsk3.TSK_FS_TYPE_FFS2: "UFS2",
        }
        return _FS_NAMES.get(fs_type, f"Unknown ({fs_type})")
    except Exception:
        return "Unknown"


def save_tsk_file(
    fs_info_or_device: str,
    tsk_file: TSKDeletedFile,
    output_path: str,
) -> bool:
    """
    Save a TSK-recovered file by reading its data blocks from the device.

    Uses pytsk3 to read the file's actual data runs (not raw offset reading),
    which handles fragmented files correctly.

    Validates data matches expected format before saving — on exFAT and
    FAT32 deleted file clusters are often quickly reallocated, so the data
    may be overwritten with unrelated content.
    """
    if not HAS_TSK:
        return False

    try:
        from .smart_filter import validate_file_data_matches_extension, validate_carved_file

        # Open device and filesystem
        try:
            img_info = pytsk3.Img_Info(tsk_file.raw_device)
        except Exception:
            img_info = RawDeviceImgInfo(tsk_file.raw_device)

        fs_info = pytsk3.FS_Info(img_info)

        # Open the file by inode
        file_entry = fs_info.open_meta(tsk_file.inode)

        # Read the first 4KB to validate data matches expected format
        try:
            header_data = file_entry.read_random(0, min(4096, tsk_file.size))
        except Exception as e:
            logger.warning("TSK: Cannot read data for %s (inode=%d): %s",
                          tsk_file.name, tsk_file.inode, e)
            return False

        if not header_data:
            logger.warning("TSK: Empty data for %s (inode=%d)",
                          tsk_file.name, tsk_file.inode)
            return False

        # Validate the data matches the expected extension
        if not validate_file_data_matches_extension(tsk_file.extension, header_data):
            logger.warning("TSK: Data mismatch for %s — expected .%s but data "
                          "header is %s (clusters likely overwritten, skipping)",
                          tsk_file.name, tsk_file.extension,
                          header_data[:8].hex())
            return False

        # Ensure output directory exists
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        # Read and write in chunks
        with open(output_path, "wb") as f:
            offset = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            file_size = tsk_file.size

            while offset < file_size:
                to_read = min(chunk_size, file_size - offset)
                try:
                    data = file_entry.read_random(offset, to_read)
                except Exception:
                    break
                if not data:
                    break
                f.write(data)
                offset += len(data)

        # Post-save validation: verify the saved file is actually valid
        actual_size = os.path.getsize(output_path)
        if actual_size < 1024:
            logger.warning("TSK: Saved file too small (%d bytes): %s",
                          actual_size, output_path)
            os.remove(output_path)
            return False

        # For image files, try Pillow validation on the saved file
        try:
            with open(output_path, "rb") as f:
                saved_data = f.read(min(actual_size, 10 * 1024 * 1024))
            if not validate_carved_file(tsk_file.extension, saved_data):
                logger.warning("TSK: Saved file failed validation: %s (removing)",
                              output_path)
                os.remove(output_path)
                return False
        except Exception:
            pass  # If validation itself fails, keep the file

        logger.info("TSK: Saved %s (%d bytes) -> %s",
                    tsk_file.name, tsk_file.size, output_path)
        return True

    except Exception as e:
        logger.error("TSK: Failed to save %s: %s", tsk_file.name, e)
        # Clean up partial file
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception:
                pass
        return False


def is_available() -> bool:
    """Check if pytsk3 is installed and usable."""
    return HAS_TSK
