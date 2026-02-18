"""
Filesystem Parsers — Read allocation bitmaps to identify free/unallocated clusters.

Supports full forensic free-space parsing:
  • exFAT  — Allocation Bitmap directory entry → bitmap data
  • FAT32  — FAT table: cluster value 0x00000000 = free
  • FAT12/16 — FAT table: entry value 0x000 / 0x0000 = free
  • NTFS   — $Bitmap file: each bit = 1 cluster, 0 = free

Detected (brute-force fallback):
  • ext2/3/4  — Linux native filesystem
  • HFS+/HFSX — macOS HFS Plus
  • APFS      — Apple File System (container)
  • Btrfs     — Linux B-tree filesystem
  • XFS       — SGI/Linux high-performance filesystem
  • F2FS      — Flash-Friendly FS (Android/embedded)
  • ReiserFS  — Linux journaling filesystem
  • UDF       — Universal Disk Format (optical/USB)
  • ISO 9660  — CD/DVD filesystem
  • ZFS       — Oracle/OpenZFS

Also detects partition tables:
  • GPT       — GUID Partition Table
  • MBR       — Master Boot Record

For filesystems without bitmap parsing, the scanner falls back to
brute-force scanning of the entire device, which still works —
it just scans more sectors.
"""

import os
import struct
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FilesystemInfo:
    """Result of filesystem analysis."""
    fs_type: str                    # "exfat", "fat32", "ntfs", "unknown"
    cluster_size: int               # Bytes per cluster
    total_clusters: int             # Total cluster count
    free_clusters: int              # Number of free/unallocated clusters
    free_ranges: list[tuple[int, int]]   # Sorted list of (start_byte, end_byte)
    total_free_bytes: int           # Sum of all free ranges
    data_area_offset: int           # Byte offset where cluster data starts

    @property
    def free_percent(self) -> float:
        if self.total_clusters == 0:
            return 0.0
        return (self.free_clusters / self.total_clusters) * 100

    @property
    def free_human(self) -> str:
        return _human(self.total_free_bytes)

    @property
    def allocated_percent(self) -> float:
        return 100.0 - self.free_percent


def detect_and_parse(device_path: str) -> Optional[FilesystemInfo]:
    """
    Auto-detect filesystem type and parse its allocation bitmap.
    Returns FilesystemInfo with free cluster ranges, or None if unsupported.

    For filesystems we can't parse bitmaps for (ext2/3/4, HFS+, APFS, etc.),
    returns None — the scanner will fall back to brute-force mode automatically.
    """
    try:
        with open(device_path, "rb") as dev:
            # Read first sector (boot sector)
            boot = dev.read(512)
            if len(boot) < 512:
                return None

            # Some FS magic is further in — read more if needed
            dev.seek(0)
            header_16k = dev.read(16384)

            # Detect filesystem type
            fs_type = _detect_fs(boot, header_16k)
            logger.info("Detected filesystem: %s on %s", fs_type, device_path)

            if fs_type == "exfat":
                return _parse_exfat(dev, boot)
            elif fs_type == "fat32":
                return _parse_fat32(dev, boot)
            elif fs_type in ("fat12", "fat16"):
                return _parse_fat16(dev, boot, fs_type)
            elif fs_type == "ntfs":
                return _parse_ntfs(dev, boot)
            elif fs_type in ("ext2", "ext3", "ext4"):
                return _parse_ext(dev, boot, header_16k, fs_type)
            else:
                # Filesystem detected but no bitmap parser available
                # Scanner will use brute-force mode
                logger.info(
                    "Filesystem '%s' detected — no bitmap parser, "
                    "scanner will use brute-force mode", fs_type
                )
                return None

    except PermissionError:
        logger.error("Permission denied reading %s", device_path)
        return None
    except Exception as e:
        logger.error("Filesystem parse error: %s", e)
        return None


def _detect_fs(boot: bytes, header: bytes = b"") -> str:
    """Detect filesystem type from boot sector and extended header."""

    # ── exFAT: "EXFAT   " at offset 3 ──
    if boot[3:11] == b"EXFAT   ":
        return "exfat"

    # ── NTFS: "NTFS    " at offset 3 ──
    if boot[3:11] == b"NTFS    ":
        return "ntfs"

    # ── FAT32: check for FAT32 signature ──
    if boot[82:87] == b"FAT32":
        return "fat32"

    # Also check for FAT32 by BPB structure
    bps = struct.unpack_from("<H", boot, 11)[0]
    if bps in (512, 1024, 2048, 4096):
        fat_sz16 = struct.unpack_from("<H", boot, 22)[0]
        tot_sec16 = struct.unpack_from("<H", boot, 19)[0]
        if fat_sz16 == 0 and tot_sec16 == 0:
            fat_sz32 = struct.unpack_from("<I", boot, 36)[0]
            if fat_sz32 > 0:
                return "fat32"

    # ── FAT12/FAT16 — check BS_FilSysType at offset 54 ──
    if boot[54:59] == b"FAT16":
        return "fat16"
    if boot[54:59] == b"FAT12":
        return "fat12"
    # Generic FAT detection via BPB
    if bps in (512, 1024, 2048, 4096):
        fat_sz16 = struct.unpack_from("<H", boot, 22)[0]
        if fat_sz16 > 0:
            tot_sec16 = struct.unpack_from("<H", boot, 19)[0]
            tot_sec32 = struct.unpack_from("<I", boot, 32)[0]
            total_sectors = tot_sec16 if tot_sec16 > 0 else tot_sec32
            spc = boot[13]
            if spc > 0 and total_sectors > 0:
                reserved = struct.unpack_from("<H", boot, 14)[0]
                num_fats = boot[16]
                root_entries = struct.unpack_from("<H", boot, 17)[0]
                root_sectors = ((root_entries * 32) + bps - 1) // bps
                data_sectors = total_sectors - (reserved + num_fats * fat_sz16 + root_sectors)
                total_clusters = data_sectors // spc
                if total_clusters < 4085:
                    return "fat12"
                elif total_clusters < 65525:
                    return "fat16"

    # ── ext2/3/4: superblock at offset 1024, magic 0xEF53 ──
    if len(header) >= 1024 + 88:
        ext_magic = struct.unpack_from("<H", header, 1024 + 56)[0]
        if ext_magic == 0xEF53:
            # Distinguish ext2/3/4 by feature flags
            compat = struct.unpack_from("<I", header, 1024 + 92)[0] if len(header) >= 1024 + 96 else 0
            incompat = struct.unpack_from("<I", header, 1024 + 96)[0] if len(header) >= 1024 + 100 else 0
            if incompat & 0x0040:       # EXTENTS feature
                return "ext4"
            elif compat & 0x0004:       # HAS_JOURNAL
                return "ext3"
            else:
                return "ext2"

    # ── HFS+/HFSX: signature at offset 1024, 0x482B or 0x4858 ──
    if len(header) >= 1024 + 4:
        hfs_sig = struct.unpack_from(">H", header, 1024)[0]
        if hfs_sig == 0x482B:
            return "hfs+"
        elif hfs_sig == 0x4858:
            return "hfsx"

    # ── APFS: magic "NXSB" at offset 32 (container superblock) ──
    if len(header) >= 36:
        if header[32:36] == b"NXSB":
            return "apfs"

    # ── Btrfs: magic "_BHRfS_M" at offset 0x10040 ──
    # We'd need to read further; check what we have
    if len(header) >= 0x10048:
        if header[0x10040:0x10048] == b"_BHRfS_M":
            return "btrfs"

    # ── XFS: magic "XFSB" at offset 0 ──
    if boot[:4] == b"XFSB":
        return "xfs"

    # ── F2FS: magic at offset 1024: 0xF2F52010 LE ──
    if len(header) >= 1024 + 4:
        f2fs_magic = struct.unpack_from("<I", header, 1024)[0]
        if f2fs_magic == 0xF2F52010:
            return "f2fs"

    # ── ReiserFS: magic "ReIsErFs" or "ReIsEr2Fs" at offset 0x10034 ──
    if len(header) >= 0x10044:
        reiser_magic = header[0x10034:0x1003C]
        if reiser_magic.startswith(b"ReIsEr"):
            return "reiserfs"

    # ── UDF: look for "NSR02" or "NSR03" in Volume Recognition Sequence ──
    # VRS starts at sector 16 (offset 32768) — we'd need more data
    if len(header) >= 32768 + 8:
        if header[32769:32774] == b"NSR02" or header[32769:32774] == b"NSR03":
            return "udf"

    # ── ISO 9660: "CD001" at offset 32769 ──
    if len(header) >= 32774:
        if header[32769:32774] == b"CD001":
            return "iso9660"

    # ── ZFS: check for ZFS label magic at offset 0x20000 ──
    # Would need reading further — not in our 16K header

    # ── GPT/MBR detection (whole-disk, not a filesystem) ──
    if boot[510:512] == b"\x55\xAA":
        # Valid MBR signature
        # Check if GPT: partition type 0xEE in MBR = GPT protective MBR
        if boot[450] == 0xEE:
            return "gpt"
        # Check for actual MBR partitions
        has_partitions = False
        for i in range(4):
            ptype = boot[446 + i * 16 + 4]
            if ptype != 0:
                has_partitions = True
                break
        if has_partitions:
            return "mbr"

    return "unknown"


# ─────────────────────────────────────────────────────────────
#  exFAT Parser
# ─────────────────────────────────────────────────────────────

def _parse_exfat(dev, boot: bytes) -> Optional[FilesystemInfo]:
    """
    Parse exFAT filesystem to extract free cluster bitmap.

    exFAT Boot Sector layout:
      Offset  3: FileSystemName (8 bytes) = "EXFAT   "
      Offset 64: PartitionOffset (8 bytes)
      Offset 72: VolumeLength (8 bytes, in sectors)
      Offset 80: FatOffset (4 bytes, in sectors)
      Offset 84: FatLength (4 bytes, in sectors)
      Offset 88: ClusterHeapOffset (4 bytes, in sectors)
      Offset 92: ClusterCount (4 bytes)
      Offset 96: FirstClusterOfRootDirectory (4 bytes)
      Offset 108: BytesPerSectorShift (1 byte)
      Offset 109: SectorsPerClusterShift (1 byte)
    """
    try:
        # Parse boot sector
        bytes_per_sector_shift = boot[108]
        sectors_per_cluster_shift = boot[109]
        bytes_per_sector = 1 << bytes_per_sector_shift
        sectors_per_cluster = 1 << sectors_per_cluster_shift
        bytes_per_cluster = bytes_per_sector * sectors_per_cluster

        fat_offset_sectors = struct.unpack_from("<I", boot, 80)[0]
        cluster_heap_offset_sectors = struct.unpack_from("<I", boot, 88)[0]
        cluster_count = struct.unpack_from("<I", boot, 92)[0]
        root_dir_cluster = struct.unpack_from("<I", boot, 96)[0]

        heap_offset = cluster_heap_offset_sectors * bytes_per_sector

        logger.info(
            "exFAT: sector=%d, cluster=%d (%d bytes), "
            "clusters=%d, heap_offset=0x%X, root_cluster=%d",
            bytes_per_sector, sectors_per_cluster, bytes_per_cluster,
            cluster_count, heap_offset, root_dir_cluster,
        )

        # Find the Allocation Bitmap in root directory
        bitmap_cluster, bitmap_size = _exfat_find_bitmap(
            dev, heap_offset, bytes_per_cluster, root_dir_cluster,
        )

        if bitmap_cluster is None:
            logger.warning("exFAT: Allocation Bitmap not found in root directory")
            return None

        logger.info(
            "exFAT: Allocation Bitmap at cluster %d, size %d bytes",
            bitmap_cluster, bitmap_size,
        )

        # Read the allocation bitmap
        bitmap_offset = heap_offset + (bitmap_cluster - 2) * bytes_per_cluster
        dev.seek(bitmap_offset)
        bitmap_data = dev.read(bitmap_size)

        if len(bitmap_data) < bitmap_size:
            logger.warning("exFAT: Could not read full bitmap")
            # Proceed with what we got
            bitmap_size = len(bitmap_data)

        # Parse bitmap → free cluster ranges
        free_ranges, free_count = _bitmap_to_free_ranges(
            bitmap_data, cluster_count, heap_offset, bytes_per_cluster,
        )

        total_free = sum(end - start for start, end in free_ranges)

        logger.info(
            "exFAT: %d free clusters out of %d (%.1f%%), %s free space",
            free_count, cluster_count,
            (free_count / cluster_count * 100) if cluster_count else 0,
            _human(total_free),
        )

        return FilesystemInfo(
            fs_type="exfat",
            cluster_size=bytes_per_cluster,
            total_clusters=cluster_count,
            free_clusters=free_count,
            free_ranges=free_ranges,
            total_free_bytes=total_free,
            data_area_offset=heap_offset,
        )

    except Exception as e:
        logger.error("exFAT parse error: %s", e, exc_info=True)
        return None


def _exfat_find_bitmap(
    dev, heap_offset: int, bytes_per_cluster: int, root_cluster: int,
) -> tuple[Optional[int], int]:
    """
    Read exFAT root directory to find the Allocation Bitmap entry.

    Directory entries are 32 bytes each.
    Entry type 0x81 = Allocation Bitmap Directory Entry:
      Offset  0: EntryType (1 byte) = 0x81
      Offset  1: BitmapFlags (1 byte)
      Offset 20: FirstCluster (4 bytes)
      Offset 24: DataLength (8 bytes)
    """
    # Read root directory cluster(s) — usually fits in a few clusters
    root_offset = heap_offset + (root_cluster - 2) * bytes_per_cluster
    # Read up to 16 clusters of root directory
    max_read = min(16 * bytes_per_cluster, 512 * 1024)

    dev.seek(root_offset)
    root_data = dev.read(max_read)

    # Scan 32-byte directory entries
    for i in range(0, len(root_data) - 32, 32):
        entry_type = root_data[i]

        # 0x81 = Allocation Bitmap (critical primary)
        if entry_type == 0x81:
            first_cluster = struct.unpack_from("<I", root_data, i + 20)[0]
            data_length = struct.unpack_from("<Q", root_data, i + 24)[0]
            return first_cluster, data_length

        # 0x00 = end of directory
        if entry_type == 0x00:
            break

    return None, 0


# ─────────────────────────────────────────────────────────────
#  FAT32 Parser
# ─────────────────────────────────────────────────────────────

def _parse_fat32(dev, boot: bytes) -> Optional[FilesystemInfo]:
    """
    Parse FAT32 filesystem to find free clusters.

    FAT32 BPB layout:
      Offset 11: BytesPerSector (2 bytes)
      Offset 13: SectorsPerCluster (1 byte)
      Offset 14: ReservedSectorCount (2 bytes)
      Offset 16: NumberOfFATs (1 byte)
      Offset 32: TotalSectors32 (4 bytes)
      Offset 36: FATSz32 (4 bytes, sectors per FAT)
      Offset 44: RootCluster (4 bytes)
    """
    try:
        bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]
        reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
        num_fats = boot[16]
        total_sectors = struct.unpack_from("<I", boot, 32)[0]
        fat_size_sectors = struct.unpack_from("<I", boot, 36)[0]

        if bytes_per_sector == 0 or sectors_per_cluster == 0:
            return None

        bytes_per_cluster = bytes_per_sector * sectors_per_cluster
        fat_offset = reserved_sectors * bytes_per_sector
        fat_size_bytes = fat_size_sectors * bytes_per_sector
        data_offset = (reserved_sectors + num_fats * fat_size_sectors) * bytes_per_sector
        total_data_sectors = total_sectors - (reserved_sectors + num_fats * fat_size_sectors)
        total_clusters = total_data_sectors // sectors_per_cluster

        logger.info(
            "FAT32: sector=%d, cluster=%d (%d bytes), clusters=%d, "
            "FAT at 0x%X (%d bytes), data at 0x%X",
            bytes_per_sector, sectors_per_cluster, bytes_per_cluster,
            total_clusters, fat_offset, fat_size_bytes, data_offset,
        )

        # Read the FAT (each entry is 4 bytes)
        dev.seek(fat_offset)
        # FAT has total_clusters + 2 entries (first 2 are reserved)
        fat_entries_count = total_clusters + 2
        fat_data_size = fat_entries_count * 4
        # Cap to actual FAT size
        fat_data_size = min(fat_data_size, fat_size_bytes)
        fat_data = dev.read(fat_data_size)

        if len(fat_data) < 8:
            return None

        # Parse FAT entries to find free clusters
        # Entry value 0x00000000 = free cluster
        # We start from cluster 2 (first two entries are reserved)
        free_ranges: list[tuple[int, int]] = []
        free_count = 0
        run_start: Optional[int] = None

        num_entries = min(len(fat_data) // 4, fat_entries_count)

        for cluster_num in range(2, num_entries):
            entry = struct.unpack_from("<I", fat_data, cluster_num * 4)[0]
            entry &= 0x0FFFFFFF  # FAT32 uses 28 bits

            if entry == 0x00000000:
                # Free cluster
                free_count += 1
                if run_start is None:
                    run_start = cluster_num
            else:
                # Allocated — close any open run
                if run_start is not None:
                    start_byte = data_offset + (run_start - 2) * bytes_per_cluster
                    end_byte = data_offset + (cluster_num - 2) * bytes_per_cluster
                    free_ranges.append((start_byte, end_byte))
                    run_start = None

        # Close final run
        if run_start is not None:
            start_byte = data_offset + (run_start - 2) * bytes_per_cluster
            end_byte = data_offset + (num_entries - 2) * bytes_per_cluster
            free_ranges.append((start_byte, end_byte))

        total_free = sum(end - start for start, end in free_ranges)

        logger.info(
            "FAT32: %d free clusters out of %d (%.1f%%), %s, %d ranges",
            free_count, total_clusters,
            (free_count / total_clusters * 100) if total_clusters else 0,
            _human(total_free), len(free_ranges),
        )

        return FilesystemInfo(
            fs_type="fat32",
            cluster_size=bytes_per_cluster,
            total_clusters=total_clusters,
            free_clusters=free_count,
            free_ranges=free_ranges,
            total_free_bytes=total_free,
            data_area_offset=data_offset,
        )

    except Exception as e:
        logger.error("FAT32 parse error: %s", e, exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────
#  FAT12/FAT16 Parser
# ─────────────────────────────────────────────────────────────

def _parse_fat16(dev, boot: bytes, fs_type: str) -> Optional[FilesystemInfo]:
    """
    Parse FAT12 or FAT16 filesystem to find free clusters.

    FAT12/16 BPB:
      Offset 11: BytesPerSector (2 bytes)
      Offset 13: SectorsPerCluster (1 byte)
      Offset 14: ReservedSectorCount (2 bytes)
      Offset 16: NumberOfFATs (1 byte)
      Offset 17: RootEntryCount (2 bytes)
      Offset 19: TotalSectors16 (2 bytes, 0 if > 65535)
      Offset 22: FATSize16 (2 bytes)
      Offset 32: TotalSectors32 (4 bytes, used if TotalSectors16 == 0)
    """
    try:
        bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]
        reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
        num_fats = boot[16]
        root_entry_count = struct.unpack_from("<H", boot, 17)[0]
        total_sectors_16 = struct.unpack_from("<H", boot, 19)[0]
        fat_size_sectors = struct.unpack_from("<H", boot, 22)[0]
        total_sectors_32 = struct.unpack_from("<I", boot, 32)[0]

        if bytes_per_sector == 0 or sectors_per_cluster == 0 or fat_size_sectors == 0:
            return None

        total_sectors = total_sectors_16 if total_sectors_16 > 0 else total_sectors_32
        bytes_per_cluster = bytes_per_sector * sectors_per_cluster

        # Root directory size (FAT12/16 have fixed root dir)
        root_dir_sectors = ((root_entry_count * 32) + bytes_per_sector - 1) // bytes_per_sector
        fat_offset = reserved_sectors * bytes_per_sector
        fat_size_bytes = fat_size_sectors * bytes_per_sector
        data_offset = (reserved_sectors + num_fats * fat_size_sectors + root_dir_sectors) * bytes_per_sector
        data_sectors = total_sectors - (reserved_sectors + num_fats * fat_size_sectors + root_dir_sectors)
        total_clusters = data_sectors // sectors_per_cluster

        is_fat12 = (fs_type == "fat12")

        logger.info(
            "%s: sector=%d, cluster=%d (%d bytes), clusters=%d, "
            "FAT at 0x%X, data at 0x%X, root_entries=%d",
            fs_type.upper(), bytes_per_sector, sectors_per_cluster,
            bytes_per_cluster, total_clusters, fat_offset, data_offset,
            root_entry_count,
        )

        # Read the FAT
        dev.seek(fat_offset)
        fat_data = dev.read(fat_size_bytes)
        if len(fat_data) < 4:
            return None

        free_ranges: list[tuple[int, int]] = []
        free_count = 0
        run_start: Optional[int] = None

        for cluster_num in range(2, total_clusters + 2):
            if is_fat12:
                # FAT12: 12 bits per entry, packed
                byte_pos = (cluster_num * 3) // 2
                if byte_pos + 1 >= len(fat_data):
                    break
                if cluster_num & 1:
                    entry = ((fat_data[byte_pos] >> 4) |
                             (fat_data[byte_pos + 1] << 4)) & 0x0FFF
                else:
                    entry = (fat_data[byte_pos] |
                             ((fat_data[byte_pos + 1] & 0x0F) << 8)) & 0x0FFF
                is_free = (entry == 0x000)
            else:
                # FAT16: 16 bits per entry
                byte_pos = cluster_num * 2
                if byte_pos + 1 >= len(fat_data):
                    break
                entry = struct.unpack_from("<H", fat_data, byte_pos)[0]
                is_free = (entry == 0x0000)

            if is_free:
                free_count += 1
                if run_start is None:
                    run_start = cluster_num
            else:
                if run_start is not None:
                    start_byte = data_offset + (run_start - 2) * bytes_per_cluster
                    end_byte = data_offset + (cluster_num - 2) * bytes_per_cluster
                    free_ranges.append((start_byte, end_byte))
                    run_start = None

        # Close final run
        if run_start is not None:
            start_byte = data_offset + (run_start - 2) * bytes_per_cluster
            end_byte = data_offset + (min(cluster_num, total_clusters + 2) - 2) * bytes_per_cluster
            free_ranges.append((start_byte, end_byte))

        total_free = sum(end - start for start, end in free_ranges)

        logger.info(
            "%s: %d free clusters out of %d (%.1f%%), %s, %d ranges",
            fs_type.upper(), free_count, total_clusters,
            (free_count / total_clusters * 100) if total_clusters else 0,
            _human(total_free), len(free_ranges),
        )

        return FilesystemInfo(
            fs_type=fs_type,
            cluster_size=bytes_per_cluster,
            total_clusters=total_clusters,
            free_clusters=free_count,
            free_ranges=free_ranges,
            total_free_bytes=total_free,
            data_area_offset=data_offset,
        )

    except Exception as e:
        logger.error("%s parse error: %s", fs_type.upper(), e, exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────
#  ext2/3/4 Parser
# ─────────────────────────────────────────────────────────────

def _parse_ext(dev, boot: bytes, header: bytes, fs_type: str) -> Optional[FilesystemInfo]:
    """
    Parse ext2/3/4 filesystem to find free blocks via block group bitmaps.

    ext2/3/4 superblock at offset 1024:
      +0:  s_inodes_count (4)
      +4:  s_blocks_count_lo (4)
      +8:  s_r_blocks_count_lo (4)
      +12: s_free_blocks_count_lo (4)
      +24: s_log_block_size (4) — block_size = 1024 << s_log_block_size
      +32: s_blocks_per_group (4)
      +88: s_magic (2) = 0xEF53
      +96: s_feature_compat (4)
      +100: s_feature_incompat (4)
      +340: s_blocks_count_hi (4) — for 64-bit mode
      +344: s_r_blocks_count_hi (4)
      +348: s_free_blocks_count_hi (4)
      +352: s_desc_size (2) — group descriptor size for 64-bit

    Block Group Descriptor (32 bytes standard, 64 bytes for 64-bit):
      +0: bg_block_bitmap_lo (4)
      +4: bg_inode_bitmap_lo (4)
      +8: bg_block_bitmap_hi (if 64-bit, offset +32 in 64-byte descriptor)
    """
    try:
        sb_offset = 1024

        # Ensure we have enough superblock data
        if len(header) < sb_offset + 360:
            dev.seek(sb_offset)
            sb_data = dev.read(1024)
        else:
            sb_data = header[sb_offset:sb_offset + 1024]

        if len(sb_data) < 264:
            return None

        # Parse superblock
        blocks_count_lo = struct.unpack_from("<I", sb_data, 4)[0]
        free_blocks_lo = struct.unpack_from("<I", sb_data, 12)[0]
        log_block_size = struct.unpack_from("<I", sb_data, 24)[0]
        blocks_per_group = struct.unpack_from("<I", sb_data, 32)[0]

        block_size = 1024 << log_block_size

        # Check for 64-bit feature (INCOMPAT_64BIT = 0x0080)
        incompat = struct.unpack_from("<I", sb_data, 96)[0] if len(sb_data) > 100 else 0
        is_64bit = bool(incompat & 0x0080)

        if is_64bit and len(sb_data) >= 352:
            blocks_count_hi = struct.unpack_from("<I", sb_data, 336)[0]
            free_blocks_hi = struct.unpack_from("<I", sb_data, 344)[0]
            total_blocks = blocks_count_lo | (blocks_count_hi << 32)
            total_free_blocks = free_blocks_lo | (free_blocks_hi << 32)
            desc_size = struct.unpack_from("<H", sb_data, 254)[0] if len(sb_data) > 256 else 32
            if desc_size < 32:
                desc_size = 32
        else:
            total_blocks = blocks_count_lo
            total_free_blocks = free_blocks_lo
            desc_size = 32

        if blocks_per_group == 0:
            return None

        num_groups = (total_blocks + blocks_per_group - 1) // blocks_per_group

        logger.info(
            "%s: block_size=%d, total_blocks=%d, free_blocks=%d, "
            "blocks_per_group=%d, groups=%d, 64bit=%s",
            fs_type.upper(), block_size, total_blocks, total_free_blocks,
            blocks_per_group, num_groups, is_64bit,
        )

        # Block Group Descriptor Table starts right after superblock
        # Superblock is at block 0 (if block_size >= 2048) or block 1 (if block_size == 1024)
        if block_size == 1024:
            gdt_offset = 2 * block_size  # block 2
        else:
            gdt_offset = block_size  # block 1

        # Read all group descriptors
        gdt_size = num_groups * desc_size
        dev.seek(gdt_offset)
        gdt_data = dev.read(gdt_size)

        if len(gdt_data) < num_groups * desc_size:
            logger.warning("%s: Could not read full GDT (%d/%d bytes)",
                           fs_type, len(gdt_data), gdt_size)
            # Use what we have
            num_groups = len(gdt_data) // desc_size

        # Parse block bitmaps from each group to find free ranges
        free_ranges: list[tuple[int, int]] = []
        total_free_counted = 0

        for group_idx in range(num_groups):
            gd_offset = group_idx * desc_size
            if gd_offset + 8 > len(gdt_data):
                break

            bitmap_block_lo = struct.unpack_from("<I", gdt_data, gd_offset)[0]
            if is_64bit and desc_size >= 40:
                bitmap_block_hi = struct.unpack_from("<I", gdt_data, gd_offset + 32)[0]
                bitmap_block = bitmap_block_lo | (bitmap_block_hi << 32)
            else:
                bitmap_block = bitmap_block_lo

            if bitmap_block == 0:
                continue

            # Read the block bitmap (one block covers blocks_per_group blocks)
            bitmap_byte_offset = bitmap_block * block_size
            # How many blocks in this group?
            group_start_block = group_idx * blocks_per_group
            blocks_in_group = min(blocks_per_group, total_blocks - group_start_block)
            bitmap_bytes_needed = (blocks_in_group + 7) // 8

            dev.seek(bitmap_byte_offset)
            bitmap = dev.read(min(bitmap_bytes_needed, block_size))

            if len(bitmap) < bitmap_bytes_needed:
                bitmap_bytes_needed = len(bitmap)

            # Parse bitmap: bit=0 → free, bit=1 → allocated
            run_start: Optional[int] = None
            for blk_idx in range(blocks_in_group):
                byte_idx = blk_idx >> 3
                bit_idx = blk_idx & 7
                if byte_idx >= len(bitmap):
                    break

                is_alloc = (bitmap[byte_idx] >> bit_idx) & 1
                abs_block = group_start_block + blk_idx

                if is_alloc == 0:
                    total_free_counted += 1
                    if run_start is None:
                        run_start = abs_block
                else:
                    if run_start is not None:
                        start_byte = run_start * block_size
                        end_byte = abs_block * block_size
                        free_ranges.append((start_byte, end_byte))
                        run_start = None

            # Close run at end of group
            if run_start is not None:
                start_byte = run_start * block_size
                end_byte = (group_start_block + blocks_in_group) * block_size
                free_ranges.append((start_byte, end_byte))

        total_free_bytes = sum(end - start for start, end in free_ranges)

        logger.info(
            "%s: %d free blocks counted, %s, %d free ranges",
            fs_type.upper(), total_free_counted,
            _human(total_free_bytes), len(free_ranges),
        )

        return FilesystemInfo(
            fs_type=fs_type,
            cluster_size=block_size,
            total_clusters=total_blocks,
            free_clusters=total_free_counted,
            free_ranges=free_ranges,
            total_free_bytes=total_free_bytes,
            data_area_offset=0,
        )

    except Exception as e:
        logger.error("%s parse error: %s", fs_type.upper(), e, exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────
#  NTFS Parser
# ─────────────────────────────────────────────────────────────

def _parse_ntfs(dev, boot: bytes) -> Optional[FilesystemInfo]:
    """
    Parse NTFS filesystem to find free clusters via $Bitmap.

    NTFS Boot Sector layout:
      Offset  3:  OemId (8 bytes) = "NTFS    "
      Offset 11:  BytesPerSector (2 bytes)
      Offset 13:  SectorsPerCluster (1 byte)
      Offset 40:  TotalSectors (8 bytes)
      Offset 48:  MFT cluster number (8 bytes)
      Offset 56:  MFTMirr cluster number (8 bytes)
      Offset 64:  ClustersPerFileRecordSegment (signed byte or power)

    $Bitmap is MFT entry #6.  It contains one bit per cluster:
      bit = 0 → free, bit = 1 → allocated.
    """
    try:
        bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]

        if bytes_per_sector == 0 or sectors_per_cluster == 0:
            return None

        bytes_per_cluster = bytes_per_sector * sectors_per_cluster
        total_sectors = struct.unpack_from("<Q", boot, 40)[0]
        mft_cluster = struct.unpack_from("<Q", boot, 48)[0]

        # File record size (offset 64): signed byte
        # If positive: clusters per record. If negative: 2^|val| bytes.
        raw_record_size = boot[64]
        if raw_record_size < 0x80:
            file_record_size = raw_record_size * bytes_per_cluster
        else:
            # Two's complement: negative value = 2^|val| bytes
            file_record_size = 1 << (256 - raw_record_size)

        total_clusters = total_sectors // sectors_per_cluster

        mft_offset = mft_cluster * bytes_per_cluster

        logger.info(
            "NTFS: sector=%d, cluster=%d (%d bytes), "
            "clusters=%d, MFT at cluster %d (0x%X), "
            "file record=%d bytes",
            bytes_per_sector, sectors_per_cluster, bytes_per_cluster,
            total_clusters, mft_cluster, mft_offset, file_record_size,
        )

        # Read $Bitmap (MFT entry #6)
        bitmap_data = _ntfs_read_bitmap(
            dev, mft_offset, file_record_size, bytes_per_cluster,
        )

        if not bitmap_data:
            logger.warning("NTFS: Could not read $Bitmap")
            return None

        # Parse bitmap → free cluster ranges
        data_area_offset = 0  # NTFS clusters start from LCN 0
        free_ranges, free_count = _ntfs_bitmap_to_free_ranges(
            bitmap_data, total_clusters, bytes_per_cluster,
        )

        total_free = sum(end - start for start, end in free_ranges)

        logger.info(
            "NTFS: %d free clusters out of %d (%.1f%%), %s, %d ranges",
            free_count, total_clusters,
            (free_count / total_clusters * 100) if total_clusters else 0,
            _human(total_free), len(free_ranges),
        )

        return FilesystemInfo(
            fs_type="ntfs",
            cluster_size=bytes_per_cluster,
            total_clusters=total_clusters,
            free_clusters=free_count,
            free_ranges=free_ranges,
            total_free_bytes=total_free,
            data_area_offset=0,
        )

    except Exception as e:
        logger.error("NTFS parse error: %s", e, exc_info=True)
        return None


def _ntfs_read_bitmap(
    dev, mft_offset: int, file_record_size: int, bytes_per_cluster: int,
) -> Optional[bytes]:
    """
    Read the $Bitmap file from NTFS MFT entry #6.

    MFT entry layout:
      Offset  0: Signature "FILE"
      Offset 20: First attribute offset (2 bytes)
      ...
      Attributes are chained; we look for $DATA attribute (type 0x80).
      $Bitmap's $DATA is usually non-resident (stored in data runs).
    """
    # MFT entry #6 is at mft_offset + 6 * file_record_size
    bitmap_entry_offset = mft_offset + 6 * file_record_size

    dev.seek(bitmap_entry_offset)
    entry = dev.read(file_record_size)

    if len(entry) < 48:
        return None

    # Verify FILE signature
    if entry[:4] != b"FILE":
        logger.debug("NTFS: $Bitmap MFT entry missing FILE signature")
        return None

    # Apply fixup array for multi-sector entries
    entry = _ntfs_apply_fixups(entry)

    # Find first attribute offset
    attr_offset = struct.unpack_from("<H", entry, 20)[0]

    # Walk attributes to find $DATA (type 0x80)
    pos = attr_offset
    while pos + 16 < len(entry):
        attr_type = struct.unpack_from("<I", entry, pos)[0]
        attr_length = struct.unpack_from("<I", entry, pos + 4)[0]

        if attr_type == 0xFFFFFFFF or attr_length == 0:
            break

        if attr_type == 0x80:  # $DATA attribute
            # Check if resident or non-resident
            non_resident = entry[pos + 8]

            if non_resident == 0:
                # Resident $DATA (unusual for $Bitmap but possible on tiny volumes)
                content_size = struct.unpack_from("<I", entry, pos + 16)[0]
                content_offset = struct.unpack_from("<H", entry, pos + 20)[0]
                data_start = pos + content_offset
                return bytes(entry[data_start:data_start + content_size])

            else:
                # Non-resident: parse data runs
                data_size = struct.unpack_from("<Q", entry, pos + 48)[0]
                run_offset = struct.unpack_from("<H", entry, pos + 32)[0]
                runs = _ntfs_parse_data_runs(entry[pos + run_offset:])

                # Read all data runs
                bitmap_data = bytearray()
                for lcn, cluster_count in runs:
                    run_byte_offset = lcn * bytes_per_cluster
                    run_byte_size = cluster_count * bytes_per_cluster
                    dev.seek(run_byte_offset)
                    bitmap_data.extend(dev.read(run_byte_size))

                    if len(bitmap_data) >= data_size:
                        break

                return bytes(bitmap_data[:data_size])

        pos += attr_length
        if attr_length == 0:
            break

    return None


def _ntfs_apply_fixups(entry: bytes) -> bytes:
    """Apply NTFS fixup array to an MFT entry (multi-sector protection)."""
    if len(entry) < 48:
        return entry

    fixup_offset = struct.unpack_from("<H", entry, 4)[0]
    fixup_count = struct.unpack_from("<H", entry, 6)[0]

    if fixup_count <= 1 or fixup_offset + fixup_count * 2 > len(entry):
        return entry

    entry = bytearray(entry)
    signature = struct.unpack_from("<H", entry, fixup_offset)[0]

    for i in range(1, fixup_count):
        sector_end = (i * 512) - 2
        if sector_end + 2 <= len(entry) and fixup_offset + i * 2 + 2 <= len(entry):
            # Verify the fixup signature matches
            current = struct.unpack_from("<H", entry, sector_end)[0]
            if current == signature:
                # Replace with actual value from fixup array
                actual = entry[fixup_offset + i * 2:fixup_offset + i * 2 + 2]
                entry[sector_end:sector_end + 2] = actual

    return bytes(entry)


def _ntfs_parse_data_runs(data: bytes) -> list[tuple[int, int]]:
    """
    Parse NTFS data runs (run list) to get (LCN, cluster_count) pairs.

    Data run encoding:
      Byte 0: high nibble = length field size, low nibble = offset field size
      Next N bytes: cluster count (little-endian)
      Next M bytes: LCN offset (little-endian, signed)
    """
    runs = []
    pos = 0
    current_lcn = 0

    while pos < len(data):
        header = data[pos]
        if header == 0:
            break

        length_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F
        pos += 1

        if pos + length_size + offset_size > len(data):
            break

        # Read cluster count
        count_bytes = data[pos:pos + length_size]
        cluster_count = int.from_bytes(count_bytes, "little", signed=False)
        pos += length_size

        # Read LCN offset (signed, relative to previous run)
        if offset_size > 0:
            offset_bytes = data[pos:pos + offset_size]
            lcn_offset = int.from_bytes(offset_bytes, "little", signed=True)
            pos += offset_size
            current_lcn += lcn_offset
        else:
            # Sparse run (no physical location) — skip
            continue

        if cluster_count > 0 and current_lcn >= 0:
            runs.append((current_lcn, cluster_count))

    return runs


def _ntfs_bitmap_to_free_ranges(
    bitmap: bytes,
    total_clusters: int,
    bytes_per_cluster: int,
) -> tuple[list[tuple[int, int]], int]:
    """
    Convert NTFS $Bitmap to free byte ranges.
    In NTFS bitmap: bit = 0 → free, bit = 1 → allocated.
    """
    free_ranges: list[tuple[int, int]] = []
    free_count = 0
    run_start: Optional[int] = None

    for cluster_idx in range(min(total_clusters, len(bitmap) * 8)):
        byte_idx = cluster_idx >> 3
        bit_idx = cluster_idx & 7

        if byte_idx >= len(bitmap):
            break

        is_allocated = (bitmap[byte_idx] >> bit_idx) & 1

        if is_allocated == 0:
            free_count += 1
            if run_start is None:
                run_start = cluster_idx
        else:
            if run_start is not None:
                start_byte = run_start * bytes_per_cluster
                end_byte = cluster_idx * bytes_per_cluster
                free_ranges.append((start_byte, end_byte))
                run_start = None

    # Close final run
    if run_start is not None:
        end_cluster = min(total_clusters, cluster_idx + 1) if total_clusters > 0 else cluster_idx + 1
        start_byte = run_start * bytes_per_cluster
        end_byte = end_cluster * bytes_per_cluster
        free_ranges.append((start_byte, end_byte))

    return free_ranges, free_count


# ─────────────────────────────────────────────────────────────
#  Bitmap → Free Ranges Converter
# ─────────────────────────────────────────────────────────────

def _bitmap_to_free_ranges(
    bitmap: bytes,
    cluster_count: int,
    heap_offset: int,
    bytes_per_cluster: int,
) -> tuple[list[tuple[int, int]], int]:
    """
    Convert an allocation bitmap to a list of (start_byte, end_byte) ranges
    for unallocated (free) clusters.

    In exFAT bitmap: bit = 0 → free, bit = 1 → allocated.
    Bit 0 of byte 0 = cluster 2, bit 1 = cluster 3, etc.
    """
    free_ranges: list[tuple[int, int]] = []
    free_count = 0
    run_start: Optional[int] = None

    for cluster_idx in range(cluster_count):
        byte_idx = cluster_idx >> 3        # cluster_idx // 8
        bit_idx = cluster_idx & 7          # cluster_idx % 8

        if byte_idx >= len(bitmap):
            break

        is_allocated = (bitmap[byte_idx] >> bit_idx) & 1

        if is_allocated == 0:
            # Free cluster
            free_count += 1
            if run_start is None:
                run_start = cluster_idx
        else:
            # Allocated — close any open run
            if run_start is not None:
                actual_start = run_start + 2  # Clusters start at 2
                actual_end = cluster_idx + 2
                start_byte = heap_offset + (actual_start - 2) * bytes_per_cluster
                end_byte = heap_offset + (actual_end - 2) * bytes_per_cluster
                free_ranges.append((start_byte, end_byte))
                run_start = None

    # Close final run
    if run_start is not None:
        actual_start = run_start + 2
        actual_end = min(cluster_count, cluster_idx + 1) + 2
        start_byte = heap_offset + (actual_start - 2) * bytes_per_cluster
        end_byte = heap_offset + (actual_end - 2) * bytes_per_cluster
        free_ranges.append((start_byte, end_byte))

    return free_ranges, free_count


# ─────────────────────────────────────────────────────────────

def _human(nbytes: int) -> str:
    s = float(nbytes)
    for u in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{s:.1f} TB"
