"""
SSD / TRIM Detection — Pre-flight check for data recovery feasibility.

CRITICAL RULE:  If SSD + TRIM is enabled, deleted data is almost certainly
gone.  TRIM tells the SSD controller to erase blocks immediately upon
deletion.  No software — not even police-grade forensic tools — can recover
TRIM'd data.  Professional tools ALWAYS check this first.

This module detects:
  1. Whether the drive is an SSD or HDD (rotational flag).
  2. Whether TRIM / UNMAP / DISCARD is enabled.
  3. Whether the filesystem was mounted with discard (Linux).

Supported platforms: macOS, Linux, Windows.
"""

import os
import re
import logging
import platform
import subprocess
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DriveHealthInfo:
    """Pre-scan drive analysis results."""
    device_path: str
    is_ssd: bool = False
    is_hdd: bool = False
    is_unknown: bool = True
    trim_enabled: bool = False
    trim_supported: bool = False
    drive_type: str = "Unknown"         # "SSD", "HDD", "NVMe", "USB", "Unknown"
    model: str = ""
    serial: str = ""
    firmware: str = ""
    connection_type: str = ""           # "USB", "SATA", "NVMe", "Thunderbolt", ""
    is_external: bool = False           # True if connected via USB/Thunderbolt
    # Recovery feasibility
    recovery_possible: bool = True
    recovery_warning: str = ""
    recovery_confidence: str = "unknown"  # "high", "medium", "low", "none"

    @property
    def summary(self) -> str:
        parts = [f"Drive: {self.drive_type}"]
        if self.model:
            parts.append(f"Model: {self.model}")
        if self.is_external:
            parts.append("External")
        if self.trim_enabled:
            parts.append("TRIM: ENABLED ⚠️")
        elif self.trim_supported:
            parts.append("TRIM: supported but disabled ✅")
        else:
            parts.append("TRIM: not supported ✅")
        parts.append(f"Recovery: {self.recovery_confidence.upper()}")
        return "  |  ".join(parts)

    @property
    def is_ssd_with_trim(self) -> bool:
        """True only for internal SSDs with active TRIM.
        External SSDs via USB rarely pass TRIM commands."""
        return self.is_ssd and self.trim_enabled and not self.is_external


def detect_drive_health(device_or_mount: str) -> DriveHealthInfo:
    """
    Analyze a drive for SSD/TRIM status before scanning.

    Args:
        device_or_mount: Raw device path (/dev/rdisk2s1) or mount point (/Volumes/USB).

    Returns:
        DriveHealthInfo with recovery feasibility assessment.
    """
    info = DriveHealthInfo(device_path=device_or_mount)
    system = platform.system()

    try:
        if system == "Darwin":
            _detect_macos(device_or_mount, info)
        elif system == "Linux":
            _detect_linux(device_or_mount, info)
        elif system == "Windows":
            _detect_windows(device_or_mount, info)
    except Exception as e:
        logger.warning("Drive health detection failed: %s", e)
        info.is_unknown = True

    # Assess recovery feasibility
    _assess_recovery(info)
    return info


# ─────────────────────────────────────────────────────────────
#  macOS Detection
# ─────────────────────────────────────────────────────────────

def _detect_macos(path: str, info: DriveHealthInfo):
    """Detect SSD/TRIM on macOS using diskutil and system_profiler."""

    # Normalize to disk identifier (strip /dev/, /dev/r, partition suffix)
    disk_id = _macos_resolve_disk_id(path)
    if not disk_id:
        return

    # diskutil info gives us: Solid State, TRIM Support, Media Name
    try:
        r = subprocess.run(
            ["diskutil", "info", disk_id],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            output = r.stdout

            # Solid State: Yes/No
            m = re.search(r"Solid State:\s*(Yes|No)", output, re.IGNORECASE)
            if m:
                if m.group(1).lower() == "yes":
                    info.is_ssd = True
                    info.is_hdd = False
                    info.is_unknown = False
                    info.drive_type = "SSD"
                else:
                    info.is_ssd = False
                    info.is_hdd = True
                    info.is_unknown = False
                    info.drive_type = "HDD"

            # Device / Media Name
            m = re.search(r"(?:Device / )?Media Name:\s*(.+)", output)
            if m:
                info.model = m.group(1).strip()

            # Protocol (NVMe, USB, SATA, Thunderbolt, PCIe, FireWire)
            m = re.search(r"Protocol:\s*(.+)", output)
            if m:
                proto = m.group(1).strip().lower()
                if "nvme" in proto:
                    info.drive_type = "NVMe SSD"
                    info.is_ssd = True
                    info.is_hdd = False
                    info.is_unknown = False
                    info.connection_type = "NVMe"
                elif "pcie" in proto or "pci" in proto:
                    info.connection_type = "PCIe"
                    if info.is_ssd:
                        info.drive_type = "PCIe SSD"
                elif "usb" in proto:
                    info.connection_type = "USB"
                    info.is_external = True
                    # Keep SSD/HDD detection from Solid State check
                    if info.is_ssd:
                        info.drive_type = "External SSD (USB)"
                    elif not info.is_hdd:
                        info.drive_type = "USB"
                elif "sata" in proto:
                    info.connection_type = "SATA"
                elif "thunderbolt" in proto:
                    info.connection_type = "Thunderbolt"
                    info.is_external = True
                    if info.is_ssd:
                        info.drive_type = "External SSD (Thunderbolt)"
                elif "firewire" in proto or "1394" in proto:
                    info.connection_type = "FireWire"
                    info.is_external = True
                    if info.is_ssd:
                        info.drive_type = "External SSD (FireWire)"

            # Internal (Yes/No)
            m = re.search(r"Device Location:\s*(Internal|External)", output, re.IGNORECASE)
            if m:
                if m.group(1).lower() == "external":
                    info.is_external = True
                    if info.is_ssd and "External" not in info.drive_type:
                        info.drive_type = f"External SSD ({info.connection_type or 'USB'})"

            # Removable Media
            m = re.search(r"Removable Media:\s*(Yes|No)", output, re.IGNORECASE)
            if m and m.group(1).lower() == "yes":
                info.is_external = True
                if info.drive_type == "Unknown":
                    info.drive_type = "Removable"

    except Exception as e:
        logger.debug("diskutil info failed: %s", e)

    # Check TRIM via system_profiler (NVMe/SATA)
    _macos_check_trim(info)


def _macos_resolve_disk_id(path: str) -> Optional[str]:
    """Resolve a path to a macOS disk identifier like 'disk2' or 'disk2s1'."""
    # Already a disk id
    if re.match(r"disk\d+", path):
        return path

    # /dev/disk2s1 or /dev/rdisk2s1
    m = re.search(r"r?disk\d+(?:s\d+)?", path)
    if m:
        return m.group(0).lstrip("r")

    # Mount point → diskutil info to get Device Identifier
    try:
        r = subprocess.run(
            ["diskutil", "info", path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            m = re.search(r"Device Identifier:\s*(disk\d+(?:s\d+)?)", r.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass

    return None


def _macos_check_trim(info: DriveHealthInfo):
    """Check TRIM support on macOS via system_profiler."""
    try:
        # Check NVMe devices
        r = subprocess.run(
            ["system_profiler", "SPNVMeDataType"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and info.model:
            # Look for our drive's section
            if info.model.lower() in r.stdout.lower() or "trim" in r.stdout.lower():
                m = re.search(r"TRIM Support:\s*(Yes|No)", r.stdout, re.IGNORECASE)
                if m:
                    info.trim_supported = True
                    info.trim_enabled = m.group(1).lower() == "yes"
                    return

        # Check SATA devices
        r = subprocess.run(
            ["system_profiler", "SPSerialATADataType"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            m = re.search(r"TRIM Support:\s*(Yes|No)", r.stdout, re.IGNORECASE)
            if m:
                info.trim_supported = True
                info.trim_enabled = m.group(1).lower() == "yes"

    except Exception as e:
        logger.debug("system_profiler TRIM check failed: %s", e)

    # Internal SSDs on modern macOS always have TRIM enabled
    if info.is_ssd and not info.trim_supported:
        # Assume TRIM is on for internal SSDs (not external)
        if info.drive_type in ("SSD", "NVMe SSD", "PCIe SSD"):
            info.trim_supported = True
            info.trim_enabled = True
            logger.info("Assuming TRIM enabled for internal %s", info.drive_type)
        elif "External SSD" in info.drive_type:
            # External SSDs usually do NOT pass TRIM via USB/Thunderbolt/FireWire
            info.trim_supported = False
            info.trim_enabled = False
            logger.info(
                "External %s — TRIM unlikely through %s enclosure",
                info.drive_type, info.connection_type or "external",
            )


# ─────────────────────────────────────────────────────────────
#  Linux Detection
# ─────────────────────────────────────────────────────────────

def _detect_linux(path: str, info: DriveHealthInfo):
    """Detect SSD/TRIM on Linux using sysfs and hdparm."""

    # Resolve to base device name (e.g., sda from /dev/sda1)
    dev_name = _linux_base_device(path)
    if not dev_name:
        return

    # Check rotational flag in sysfs: 0 = SSD, 1 = HDD
    rotational_path = f"/sys/block/{dev_name}/queue/rotational"
    try:
        with open(rotational_path) as f:
            val = f.read().strip()
            if val == "0":
                info.is_ssd = True
                info.is_hdd = False
                info.is_unknown = False
                info.drive_type = "SSD"
            elif val == "1":
                info.is_ssd = False
                info.is_hdd = True
                info.is_unknown = False
                info.drive_type = "HDD"
    except (FileNotFoundError, PermissionError):
        pass

    # Check if NVMe
    if dev_name.startswith("nvme"):
        info.is_ssd = True
        info.is_hdd = False
        info.is_unknown = False
        info.drive_type = "NVMe SSD"

    # Get model from sysfs
    model_path = f"/sys/block/{dev_name}/device/model"
    try:
        with open(model_path) as f:
            info.model = f.read().strip()
    except (FileNotFoundError, PermissionError):
        pass

    # Check TRIM/DISCARD support
    discard_path = f"/sys/block/{dev_name}/queue/discard_max_bytes"
    try:
        with open(discard_path) as f:
            val = int(f.read().strip())
            info.trim_supported = val > 0
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Check if filesystem is mounted with 'discard' option
    if info.trim_supported:
        _linux_check_mount_discard(path, info)

    # Try hdparm for detailed TRIM info (requires root)
    if info.is_ssd and not info.trim_supported:
        _linux_hdparm_trim(dev_name, info)


def _linux_base_device(path: str) -> Optional[str]:
    """Extract base block device name from path."""
    # /dev/sda1 → sda,  /dev/nvme0n1p2 → nvme0n1
    if path.startswith("/dev/"):
        dev = os.path.basename(path)
        # Strip partition: sda1 → sda, nvme0n1p2 → nvme0n1
        m = re.match(r"(nvme\d+n\d+|sd[a-z]+|vd[a-z]+|hd[a-z]+)", dev)
        if m:
            return m.group(1)
        return dev

    # Mount point → findmnt
    try:
        r = subprocess.run(
            ["findmnt", "-no", "SOURCE", path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            dev = r.stdout.strip()
            return _linux_base_device(dev)
    except Exception:
        pass
    return None


def _linux_check_mount_discard(path: str, info: DriveHealthInfo):
    """Check if the filesystem is mounted with discard (auto-TRIM)."""
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    mount_point = parts[1]
                    options = parts[3]
                    if mount_point == path or parts[0] == path:
                        if "discard" in options.split(","):
                            info.trim_enabled = True
                            return
    except (FileNotFoundError, PermissionError):
        pass

    # Also check fstab for discard
    try:
        r = subprocess.run(
            ["findmnt", "-no", "OPTIONS", path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and "discard" in r.stdout:
            info.trim_enabled = True
    except Exception:
        pass


def _linux_hdparm_trim(dev_name: str, info: DriveHealthInfo):
    """Use hdparm to check TRIM support (requires root)."""
    try:
        r = subprocess.run(
            ["hdparm", "-I", f"/dev/{dev_name}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            if "TRIM supported" in r.stdout or "Data Set Management" in r.stdout:
                info.trim_supported = True
                if "deterministic read" in r.stdout.lower():
                    info.trim_enabled = True
    except (FileNotFoundError, PermissionError):
        pass


# ─────────────────────────────────────────────────────────────
#  Windows Detection
# ─────────────────────────────────────────────────────────────

def _detect_windows(path: str, info: DriveHealthInfo):
    """Detect SSD/TRIM on Windows using PowerShell/WMI."""

    drive_letter = path.rstrip(":\\").replace("\\\\.\\", "")
    if len(drive_letter) > 2:
        drive_letter = drive_letter[0]

    # Get physical disk info via PowerShell
    try:
        # Get disk number for the drive letter
        cmd = (
            f"Get-Partition -DriveLetter '{drive_letter}' | "
            f"Get-Disk | Select MediaType, Model, SerialNumber, "
            f"FirmwareVersion | ConvertTo-Json"
        )
        r = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and r.stdout.strip():
            import json
            data = json.loads(r.stdout)
            media_type = str(data.get("MediaType", "")).lower()

            if "ssd" in media_type or media_type == "4":
                info.is_ssd = True
                info.is_hdd = False
                info.is_unknown = False
                info.drive_type = "SSD"
            elif "hdd" in media_type or media_type == "3":
                info.is_ssd = False
                info.is_hdd = True
                info.is_unknown = False
                info.drive_type = "HDD"

            info.model = str(data.get("Model", "")).strip()
            info.serial = str(data.get("SerialNumber", "")).strip()
            info.firmware = str(data.get("FirmwareVersion", "")).strip()
    except Exception as e:
        logger.debug("PowerShell disk info failed: %s", e)

    # Check TRIM (Windows calls it "Optimize" for SSDs)
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             "fsutil behavior query DisableDeleteNotify"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            # DisableDeleteNotify = 0 means TRIM IS enabled
            # DisableDeleteNotify = 1 means TRIM IS disabled
            output = r.stdout.lower()
            if "disabledeletenotify = 0" in output or "= 0" in output:
                info.trim_supported = True
                info.trim_enabled = True
            elif "disabledeletenotify = 1" in output or "= 1" in output:
                info.trim_supported = True
                info.trim_enabled = False
    except Exception as e:
        logger.debug("fsutil TRIM check failed: %s", e)


# ─────────────────────────────────────────────────────────────
#  Recovery Feasibility Assessment
# ─────────────────────────────────────────────────────────────

def _assess_recovery(info: DriveHealthInfo):
    """Determine recovery feasibility based on drive characteristics."""

    dtype = info.drive_type.lower()

    if info.is_ssd and info.trim_enabled and info.is_external:
        # ── External SSD via USB/Thunderbolt/FireWire — TRIM often NOT passed ──
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.recovery_warning = (
            f"⚡ External SSD detected ({info.connection_type or 'USB'}).\n\n"
            f"Most {info.connection_type or 'USB'} enclosures do NOT pass TRIM commands\n"
            "to the drive. Deleted data likely still exists on disk.\n\n"
            "Recovery chances: MEDIUM to HIGH.\n"
            "SSD wear-leveling may affect some results.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM"
        )

    elif "external ssd" in dtype and not info.trim_enabled:
        # ── External SSD without TRIM — good recovery chances ──
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.recovery_warning = (
            f"⚡ External SSD detected ({info.connection_type or 'USB'}).\n\n"
            "TRIM is NOT active through the enclosure.\n"
            "Deleted data should still be on the drive.\n\n"
            "Recovery chances: MEDIUM to HIGH.\n"
            "SSD wear-leveling may affect some results.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM-HIGH"
        )

    elif info.is_ssd and info.trim_enabled:
        # ── Internal SSD + TRIM — recovery difficult but worth trying ──
        info.recovery_possible = True
        info.recovery_confidence = "low"
        info.recovery_warning = (
            "⚠️ SSD with TRIM ENABLED detected.\n\n"
            "TRIM erases deleted blocks at hardware level, making\n"
            "recovery difficult. However, scanning is still worth trying:\n\n"
            "✓ Recently deleted files (seconds/minutes ago) may survive\n"
            "  if TRIM hasn't executed yet\n"
            "✓ Large files may be partially recoverable\n"
            "✓ Filesystem metadata/journal may contain references\n"
            "✓ SSD garbage collection varies by manufacturer\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "TRIM: Active\n"
            "Confidence: LOW — but recovery will be attempted"
        )

    elif info.is_ssd and info.trim_supported and not info.trim_enabled:
        # SSD but TRIM disabled — unusual, some recovery possible
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.recovery_warning = (
            "⚠️ SSD detected, but TRIM appears DISABLED.\n\n"
            "Recovery MAY be possible since TRIM is not active.\n"
            "However, SSD wear-leveling can still affect results.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM"
        )

    elif info.is_ssd and not info.trim_supported:
        # SSD without TRIM support (older SSD or USB flash)
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.recovery_warning = (
            "⚠️ SSD/Flash drive without TRIM support detected.\n\n"
            "Recovery is possible, but wear-leveling may affect results.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM"
        )

    elif "usb" in dtype or "pendrive" in dtype or "flash" in dtype:
        # USB flash drive — medium recovery (no TRIM usually, but FTL exists)
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.is_unknown = False
        info.recovery_warning = (
            "🔌 USB Flash Drive detected.\n\n"
            "USB drives do not use TRIM — deleted data persists until\n"
            "overwritten. Recovery chances are MEDIUM to HIGH.\n\n"
            "Flash Translation Layer (FTL) may remap blocks internally,\n"
            "but most data should still be recoverable.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM-HIGH"
        )

    elif "sd card" in dtype or "memory card" in dtype or "cf card" in dtype:
        # SD / CF / Memory cards — medium recovery
        info.recovery_possible = True
        info.recovery_confidence = "medium"
        info.is_unknown = False
        info.recovery_warning = (
            "💳 Memory Card (SD/CF) detected.\n\n"
            "Memory cards do not use TRIM. Deleted data persists until\n"
            "overwritten. Recovery chances are MEDIUM to HIGH.\n\n"
            "Avoid writing new data to the card before recovery.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: MEDIUM-HIGH"
        )

    elif "emmc" in dtype:
        # eMMC — some devices support TRIM/DISCARD
        info.recovery_possible = True
        if info.trim_enabled:
            info.recovery_confidence = "low"
            info.recovery_warning = (
                "📱 eMMC storage with DISCARD detected.\n\n"
                "eMMC with active DISCARD may have erased deleted blocks.\n"
                "Recovery chances are LOW.\n\n"
                f"Drive: {info.model or info.drive_type}\n"
                "Confidence: LOW"
            )
        else:
            info.recovery_confidence = "medium"
            info.recovery_warning = (
                "📱 eMMC storage detected.\n\n"
                "eMMC without DISCARD preserves deleted data.\n"
                "Recovery chances are MEDIUM.\n\n"
                f"Drive: {info.model or info.drive_type}\n"
                "Confidence: MEDIUM"
            )

    elif "optical" in dtype or "cd" in dtype or "dvd" in dtype:
        # Optical media — data is usually permanent
        info.recovery_possible = True
        info.recovery_confidence = "high"
        info.is_unknown = False
        info.recovery_warning = (
            "💿 Optical disc detected.\n\n"
            "Data on optical media (CD/DVD/Blu-ray) is typically permanent.\n"
            "Recovery of readable sectors has HIGH confidence.\n"
            "Damaged/scratched areas may have errors.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: HIGH (for readable sectors)"
        )

    elif "virtual" in dtype:
        # Virtual disk (VM) — excellent recovery
        info.recovery_possible = True
        info.recovery_confidence = "high"
        info.is_unknown = False
        info.recovery_warning = (
            "🖥️ Virtual disk detected.\n\n"
            "Virtual disks (VMware/VirtualBox/Hyper-V) do not have\n"
            "hardware-level TRIM. Deleted data should be fully recoverable.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: HIGH"
        )

    elif "disk image" in dtype:
        # Disk image file — excellent recovery
        info.recovery_possible = True
        info.recovery_confidence = "high"
        info.is_unknown = False
        info.recovery_warning = (
            "📀 Disk image file detected.\n\n"
            "Disk images are static snapshots — all data including deleted\n"
            "files is preserved exactly as captured.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: HIGH"
        )

    elif info.is_hdd:
        # HDD — best case for recovery
        info.recovery_possible = True
        info.recovery_confidence = "high"
        info.recovery_warning = (
            "✅ HDD detected — best conditions for data recovery.\n\n"
            "Deleted files remain on disk until overwritten.\n"
            "The sooner you scan, the better the chances.\n\n"
            f"Drive: {info.model or info.drive_type}\n"
            "Confidence: HIGH"
        )

    else:
        # Unknown drive type
        info.recovery_possible = True
        info.recovery_confidence = "unknown"
        info.recovery_warning = (
            "ℹ️ Could not determine drive type.\n\n"
            "Recovery will be attempted, but results depend on\n"
            "the actual hardware.\n\n"
            "• USB flash / SD card: MEDIUM-HIGH\n"
            "• External HDD: HIGH\n"
            "• SSD with TRIM: NONE\n"
            "• Disk image: HIGH"
        )
