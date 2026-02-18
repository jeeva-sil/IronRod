"""
High-Performance Disk Reader — mmap + empty-block skipping + sector alignment.

PROFESSIONAL APPROACH
─────────────────────
1. Memory-mapped I/O (mmap) for zero-copy reads — the OS handles paging.
2. Sector-aligned reads (512-byte boundaries) — required for raw devices.
3. Empty block skipping — skip all-zero chunks (TRIM'd / never-written).
4. Fallback to plain read() if mmap fails (works on all platforms).

Performance impact:
  • mmap:          2–5x faster than read() on large sequential scans.
  • Block skipping: 2–30x faster on drives with large empty regions.
  • Sector align:   Required for correctness on raw block devices.
"""

import os
import mmap
import logging
from typing import Optional, BinaryIO

logger = logging.getLogger(__name__)

# Sector size (standard for all modern drives)
SECTOR_SIZE = 512

# Precomputed zero block for fast comparison
_ZERO_4MB = b"\x00" * (4 * 1024 * 1024)
_ZERO_1MB = b"\x00" * (1 * 1024 * 1024)


def align_down(offset: int, alignment: int = SECTOR_SIZE) -> int:
    """Round offset DOWN to the nearest sector boundary."""
    return (offset // alignment) * alignment


def align_up(offset: int, alignment: int = SECTOR_SIZE) -> int:
    """Round offset UP to the nearest sector boundary."""
    return ((offset + alignment - 1) // alignment) * alignment


def is_empty_block(data: bytes) -> bool:
    """
    Fast check if a data block is entirely zeros.

    Uses memoryview comparison for speed — avoids Python-level iteration.
    A zero block means TRIM'd / never-written / wiped — cannot contain
    recoverable data.
    """
    length = len(data)
    if length == 0:
        return True

    # Fast path: compare against precomputed zero block
    if length == len(_ZERO_4MB):
        return data == _ZERO_4MB
    if length == len(_ZERO_1MB):
        return data == _ZERO_1MB

    # General case: check first/last bytes first (fast reject)
    if data[0] != 0 or data[-1] != 0:
        return False

    # Sample check: test 8 evenly-spaced positions before full comparison
    step = max(1, length // 8)
    for i in range(0, length, step):
        if data[i] != 0:
            return False

    # Full comparison (only reached if samples are all zero)
    return data == b"\x00" * length


def is_low_entropy_block(data: bytes, threshold: int = 4) -> bool:
    """
    Quick heuristic: if a block has fewer than `threshold` unique byte values,
    it's unlikely to contain file data. Useful for skipping fill patterns
    (0xAA, 0xFF, etc.) beyond just zeros.
    """
    if len(data) < 512:
        return False
    # Sample 256 bytes evenly spaced
    step = max(1, len(data) // 256)
    unique = set()
    for i in range(0, len(data), step):
        unique.add(data[i])
        if len(unique) >= threshold:
            return False
    return True


class DiskReader:
    """
    High-performance disk reader with mmap support and empty-block skipping.

    Usage:
        reader = DiskReader(file_handle, total_size)
        for offset, chunk in reader.iter_chunks(block_size=4*1024*1024):
            # process chunk
            ...
        reader.close()

    Or for random access:
        data = reader.read_at(offset, size)
    """

    def __init__(
        self,
        fd: BinaryIO,
        total_size: int,
        use_mmap: bool = True,
    ):
        self._fd = fd
        self._size = total_size
        self._mmap: Optional[mmap.mmap] = None
        self._using_mmap = False

        if use_mmap and total_size > 0:
            self._try_mmap()

    def _try_mmap(self):
        """Attempt to memory-map the file/device."""
        try:
            # mmap the entire file for read-only access
            # For very large devices (> 4GB on 32-bit), this may fail
            # — we fall back to plain reads
            self._mmap = mmap.mmap(
                self._fd.fileno(),
                0,  # Map entire file
                access=mmap.ACCESS_READ,
            )
            self._using_mmap = True
            logger.info(
                "mmap enabled: %d bytes (%.1f GB)",
                self._size, self._size / (1024 ** 3),
            )
        except (OSError, ValueError, OverflowError) as e:
            # Common failures:
            #   - Device too large for 32-bit address space
            #   - Raw device doesn't support mmap on some OS
            #   - Permission issues
            logger.info("mmap unavailable (%s), using buffered reads", e)
            self._mmap = None
            self._using_mmap = False

    @property
    def is_mmap(self) -> bool:
        return self._using_mmap

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, size: int) -> bytes:
        """
        Read `size` bytes starting at `offset`.

        Uses mmap slice if available (zero-copy), otherwise seeks+reads.
        """
        if offset < 0 or offset >= self._size:
            return b""
        size = min(size, self._size - offset)
        if size <= 0:
            return b""

        if self._using_mmap and self._mmap is not None:
            try:
                return self._mmap[offset:offset + size]
            except (IndexError, ValueError):
                pass

        # Fallback: seek + read
        self._fd.seek(offset)
        return self._fd.read(size)

    def iter_chunks(
        self,
        start: int = 0,
        end: int = 0,
        block_size: int = 4 * 1024 * 1024,
        overlap: int = 65536,
        skip_empty: bool = True,
        sector_align: bool = True,
    ):
        """
        Iterate over the device in chunks, yielding (offset, data) tuples.

        Args:
            start:        Starting byte offset.
            end:          Ending byte offset (0 = device end).
            block_size:   Bytes per read (default 4 MB).
            overlap:      Overlap between chunks to catch signatures at boundaries.
            skip_empty:   Skip all-zero blocks (TRIM'd regions).
            sector_align: Align offsets to 512-byte boundaries.

        Yields:
            (offset, chunk_data) tuples.
            Skipped blocks yield nothing (caller never sees them).
        """
        if end <= 0:
            end = self._size
        end = min(end, self._size)

        if sector_align:
            start = align_down(start)

        offset = start
        skipped_bytes = 0

        while offset < end:
            read_size = min(block_size, end - offset)
            if read_size <= 0:
                break

            chunk = self.read_at(offset, read_size)
            if not chunk:
                break

            actual_len = len(chunk)

            # Skip empty blocks
            if skip_empty and actual_len >= SECTOR_SIZE:
                if is_empty_block(chunk):
                    skipped_bytes += actual_len
                    offset += actual_len  # No overlap needed for empty blocks
                    continue

            yield offset, chunk

            # Advance with overlap
            advance = actual_len - overlap
            if advance <= 0:
                advance = actual_len
            offset += advance

        if skipped_bytes > 0:
            logger.info(
                "Skipped %.1f MB of empty (zero) blocks",
                skipped_bytes / (1024 * 1024),
            )

    def iter_ranges(
        self,
        ranges: list[tuple[int, int]],
        block_size: int = 4 * 1024 * 1024,
        overlap: int = 65536,
        skip_empty: bool = True,
    ):
        """
        Iterate over specific byte ranges (forensic mode — unallocated clusters only).

        Args:
            ranges:     List of (start_byte, end_byte) tuples.
            block_size: Bytes per read.
            overlap:    Overlap between chunks within each range.
            skip_empty: Skip zero-filled blocks.

        Yields:
            (range_index, offset, chunk_data) tuples.
        """
        for range_idx, (range_start, range_end) in enumerate(ranges):
            for offset, chunk in self.iter_chunks(
                start=range_start,
                end=range_end,
                block_size=block_size,
                overlap=overlap,
                skip_empty=skip_empty,
            ):
                yield range_idx, offset, chunk

    def close(self):
        """Release mmap resources."""
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception:
                pass
            self._mmap = None
            self._using_mmap = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
