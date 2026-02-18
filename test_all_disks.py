#!/usr/bin/env python3
"""Test all disk type support: filesystem detection, drive info, recovery assessment."""

import struct
from recovery.filesystem import detect_and_parse, _detect_fs
from recovery.scanner import DriveInfo, DiskScanner
from recovery.trim_detect import detect_drive_health, _assess_recovery, DriveHealthInfo


def test_drive_info():
    """Test DriveInfo with new fields."""
    print("─── DriveInfo Display ───")

    # HDD
    d = DriveInfo(
        device_path="/dev/sda1", mount_point="/mnt", label="Test",
        filesystem="ext4", total_size=500_000_000_000,
        drive_type="HDD", bus_protocol="SATA",
    )
    print(f"  HDD: {d.display_name}")
    assert d.type_icon == "💾"

    # NVMe SSD (unmounted)
    d2 = DriveInfo(
        device_path="/dev/nvme0n1p1", mount_point="", label="NVMe Drive",
        filesystem="ext4", total_size=1_000_000_000_000,
        drive_type="NVMe SSD", is_mounted=False, bus_protocol="NVMe",
    )
    print(f"  NVMe: {d2.display_name}")
    assert d2.type_icon == "⚡"
    assert "(unmounted)" in d2.display_name

    # USB Drive
    d3 = DriveInfo(
        device_path="/dev/sdb1", mount_point="/media/usb", label="MY USB",
        filesystem="FAT32", total_size=32_000_000_000,
        drive_type="USB Drive", bus_protocol="USB",
    )
    print(f"  USB: {d3.display_name}")
    assert d3.type_icon == "🔌"

    # SD Card
    d4 = DriveInfo(
        device_path="/dev/mmcblk0p1", mount_point="/media/sd", label="",
        filesystem="exFAT", total_size=64_000_000_000,
        drive_type="SD Card", bus_protocol="SD",
    )
    print(f"  SD: {d4.display_name}")
    assert d4.type_icon == "💳"

    # Disk Image
    d5 = DriveInfo(
        device_path="/tmp/disk.img", mount_point="", label="disk.img",
        filesystem="Image", total_size=8_000_000_000,
        drive_type="Disk Image", is_mounted=False, bus_protocol="File",
    )
    print(f"  Image: {d5.display_name}")
    assert d5.type_icon == "📀"

    print("  ✅ All DriveInfo tests passed\n")


def test_filesystem_detection():
    """Test _detect_fs for all supported filesystem types."""
    print("─── Filesystem Detection ───")

    # exFAT
    boot = bytearray(512)
    boot[3:11] = b"EXFAT   "
    assert _detect_fs(bytes(boot)) == "exfat"
    print("  exFAT: ✅")

    # NTFS
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    assert _detect_fs(bytes(boot)) == "ntfs"
    print("  NTFS: ✅")

    # FAT32
    boot = bytearray(512)
    boot[82:87] = b"FAT32"
    assert _detect_fs(bytes(boot)) == "fat32"
    print("  FAT32: ✅")

    # FAT16
    boot = bytearray(512)
    boot[54:59] = b"FAT16"
    assert _detect_fs(bytes(boot)) == "fat16"
    print("  FAT16: ✅")

    # FAT12
    boot = bytearray(512)
    boot[54:59] = b"FAT12"
    assert _detect_fs(bytes(boot)) == "fat12"
    print("  FAT12: ✅")

    # ext4
    header = bytearray(16384)
    struct.pack_into("<H", header, 1024 + 56, 0xEF53)
    struct.pack_into("<I", header, 1024 + 96, 0x0040)  # EXTENTS
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "ext4"
    print("  ext4: ✅")

    # ext3
    header = bytearray(16384)
    struct.pack_into("<H", header, 1024 + 56, 0xEF53)
    struct.pack_into("<I", header, 1024 + 92, 0x0004)  # HAS_JOURNAL
    struct.pack_into("<I", header, 1024 + 96, 0x0000)
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "ext3"
    print("  ext3: ✅")

    # ext2
    header = bytearray(16384)
    struct.pack_into("<H", header, 1024 + 56, 0xEF53)
    struct.pack_into("<I", header, 1024 + 92, 0x0000)
    struct.pack_into("<I", header, 1024 + 96, 0x0000)
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "ext2"
    print("  ext2: ✅")

    # XFS
    boot = bytearray(512)
    boot[:4] = b"XFSB"
    assert _detect_fs(bytes(boot), bytes(boot)) == "xfs"
    print("  XFS: ✅")

    # APFS
    header = bytearray(16384)
    header[32:36] = b"NXSB"
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "apfs"
    print("  APFS: ✅")

    # HFS+
    header = bytearray(16384)
    struct.pack_into(">H", header, 1024, 0x482B)
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "hfs+"
    print("  HFS+: ✅")

    # HFSX
    header = bytearray(16384)
    struct.pack_into(">H", header, 1024, 0x4858)
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "hfsx"
    print("  HFSX: ✅")

    # F2FS
    header = bytearray(16384)
    struct.pack_into("<I", header, 1024, 0xF2F52010)
    assert _detect_fs(bytes(header[:512]), bytes(header)) == "f2fs"
    print("  F2FS: ✅")

    # GPT (protective MBR)
    boot = bytearray(512)
    boot[510:512] = b"\x55\xAA"
    boot[450] = 0xEE  # GPT protective partition
    assert _detect_fs(bytes(boot), bytes(boot)) == "gpt"
    print("  GPT: ✅")

    # MBR
    boot = bytearray(512)
    boot[510:512] = b"\x55\xAA"
    boot[446 + 4] = 0x07  # NTFS partition type
    assert _detect_fs(bytes(boot), bytes(boot)) == "mbr"
    print("  MBR: ✅")

    print("  ✅ All filesystem detection tests passed\n")


def test_recovery_assessment():
    """Test recovery confidence for different drive types."""
    print("─── Recovery Assessment ───")

    tests = [
        ("SSD+TRIM", {"is_ssd": True, "trim_enabled": True}, "none"),
        ("SSD-noTRIM", {"is_ssd": True, "trim_supported": True}, "medium"),
        ("HDD", {"is_hdd": True, "is_unknown": False}, "high"),
        ("USB Drive", {"drive_type": "USB Drive"}, "medium"),
        ("SD Card", {"drive_type": "SD Card"}, "medium"),
        ("eMMC", {"drive_type": "eMMC"}, "medium"),
        ("eMMC+TRIM", {"drive_type": "eMMC", "trim_enabled": True}, "low"),
        ("Optical", {"drive_type": "Optical"}, "high"),
        ("Virtual", {"drive_type": "Virtual"}, "high"),
        ("Disk Image", {"drive_type": "Disk Image"}, "high"),
    ]

    for name, attrs, expected in tests:
        h = DriveHealthInfo(device_path="/test")
        for k, v in attrs.items():
            setattr(h, k, v)
        _assess_recovery(h)
        status = "✅" if h.recovery_confidence == expected else "❌"
        print(f"  {name}: {h.recovery_confidence} (expected: {expected}) {status}")
        assert h.recovery_confidence == expected, \
            f"Failed {name}: got {h.recovery_confidence}, expected {expected}"

    print("  ✅ All recovery assessment tests passed\n")


def test_list_drives():
    """Test that list_drives works on this platform."""
    print("─── Drive Listing ───")
    drives = DiskScanner.list_drives()
    print(f"  Found {len(drives)} drives:")
    for d in drives:
        print(f"    {d.display_name}")
        print(f"      Type: {d.drive_type}, Bus: {d.bus_protocol}, "
              f"Mounted: {d.is_mounted}")
    print("  ✅ Drive listing works\n")


if __name__ == "__main__":
    test_drive_info()
    test_filesystem_detection()
    test_recovery_assessment()
    test_list_drives()
    print("═══════════════════════════════════════")
    print("  ✅  ALL TESTS PASSED — Universal disk support ready!")
    print("═══════════════════════════════════════")
