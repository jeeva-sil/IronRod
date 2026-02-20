#!/usr/bin/env python3
"""
Deleted Photo & Video Recovery — Entry Point.

Usage:
    python main.py              # GUI mode
    sudo python main.py         # GUI with raw disk access
    sudo python main.py --cli   # Terminal mode
"""

APP_VERSION = "1.0.6"

import os
import sys
import time
import argparse
import platform
import subprocess


def _request_admin_privileges():
    """
    Re-launch this process with admin (root) privileges.
    - macOS: opens Terminal.app with sudo (needed for GUI display access)
    - Linux: uses pkexec or sudo
    - Windows: uses UAC elevation via ShellExecute
    Returns True if already running as admin, otherwise re-launches and exits.
    """
    _sys = platform.system()

    if _sys in ("Darwin", "Linux"):
        if os.geteuid() == 0:
            return True  # Already root

        if _sys == "Darwin":
            import shlex

            if getattr(sys, 'frozen', False):
                # Running as .app bundle
                app_exe = sys.executable
                parts = [app_exe] + sys.argv[1:] + ["--no-elevate"]
            else:
                # Running as script
                python_exe = sys.executable
                script = os.path.abspath(sys.argv[0])
                parts = [python_exe, script] + sys.argv[1:] + ["--no-elevate"]

            # Show native macOS password dialog
            prompt_script = (
                'display dialog '
                '"IronRod needs administrator privileges to access disk devices." '
                'default answer "" with hidden answer '
                'buttons {"Cancel", "OK"} default button "OK" '
                'with title "Authentication Required" '
                'with icon caution'
            )
            try:
                result = subprocess.run(
                    ["osascript", "-e", prompt_script],
                    capture_output=True, text=True, timeout=120,
                )
            except (subprocess.TimeoutExpired, Exception):
                print("Authentication timed out. Run with: sudo", " ".join(parts))
                sys.exit(1)

            if result.returncode != 0:
                # User clicked Cancel
                sys.exit(0)

            # Parse password from "button returned:OK, text returned:<password>"
            password = ""
            for part in result.stdout.strip().split(", "):
                if part.startswith("text returned:"):
                    password = part[len("text returned:"):]
                    break

            # Re-launch with sudo -S, piping the password via stdin.
            # This preserves the current display/GUI context.
            try:
                proc = subprocess.Popen(
                    ["sudo", "-S"] + parts,
                    stdin=subprocess.PIPE,
                    env=os.environ.copy(),
                )
                proc.stdin.write((password + "\n").encode())
                proc.stdin.flush()
                proc.stdin.close()
                proc.wait()
            except Exception:
                shell_cmd = " ".join(shlex.quote(p) for p in parts)
                print(f"Run with: sudo {shell_cmd}")
            sys.exit(0)

        elif _sys == "Linux":
            python_exe = sys.executable
            script = os.path.abspath(sys.argv[0])
            args_list = sys.argv[1:]

            if getattr(sys, 'frozen', False):
                exec_args = [sys.executable] + args_list
            else:
                exec_args = [python_exe, script] + args_list

            # Try pkexec first (graphical), then fallback to sudo
            for elevate_cmd in (["pkexec"], ["sudo"]):
                try:
                    os.execvp(elevate_cmd[0], elevate_cmd + exec_args)
                except FileNotFoundError:
                    continue
            print("Could not elevate privileges. Run with: sudo", " ".join(exec_args))
            sys.exit(1)

    elif _sys == "Windows":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True  # Already admin
        except Exception:
            return True  # Can't check, assume OK

        # Re-launch with UAC elevation
        if getattr(sys, 'frozen', False):
            exe = sys.executable
            params = " ".join(sys.argv[1:])
        else:
            exe = sys.executable
            params = f'"{os.path.abspath(sys.argv[0])}" ' + " ".join(sys.argv[1:])

        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, None, 1
            )
        except Exception:
            print("Admin privileges required. Right-click → Run as Administrator.")
        sys.exit(0)

    return True


def cli_mode(args):
    from recovery.scanner import DiskScanner, ScanProgress
    from recovery.signatures import get_all_categories
    from recovery.trim_detect import detect_drive_health

    print("=" * 60)
    print(f"  📸 IronRod Data Recovery  v{APP_VERSION}")
    print("  Raw binary file carving from disk sectors")
    print("=" * 60)
    print()

    scanner = DiskScanner()

    if not args.device:
        print("Available drives:")
        print("-" * 50)
        drives = DiskScanner.list_drives()
        if not drives:
            print("  No drives found.")
            sys.exit(1)
        for i, d in enumerate(drives):
            print(f"  [{i}] {d.display_name}")
            print(f"      Device: {d.device_path}")
            print(f"      Free: {d.free_human}")
            print()
        try:
            choice = int(input("Select drive: "))
            if 0 <= choice < len(drives):
                device = drives[choice].mount_point
            else:
                print("Invalid.")
                sys.exit(1)
        except (ValueError, EOFError):
            print("Invalid.")
            sys.exit(1)
    else:
        device = args.device

    # ── SSD + TRIM detection ──
    if not args.skip_trim_check:
        print("🔍 Detecting drive type (SSD/HDD) and TRIM status...")
        try:
            health = detect_drive_health(device)
            print(f"   {health.summary}")
            print()

            if health.is_ssd_with_trim:
                print("=" * 60)
                print("  🛑 WARNING: SSD + TRIM DETECTED")
                print("=" * 60)
                print()
                print("  TRIM erases deleted blocks at the hardware level.")
                print("  No software can recover TRIM'd data.")
                print(f"  Drive: {health.model or health.drive_type}")
                print(f"  TRIM:  ENABLED")
                print(f"  Recovery confidence: NONE")
                print()
                if not args.force:
                    try:
                        resp = input("  Continue anyway? [y/N]: ").strip().lower()
                        if resp != "y":
                            print("  Aborted.")
                            sys.exit(0)
                    except (EOFError, KeyboardInterrupt):
                        print("\n  Aborted.")
                        sys.exit(0)
                print()
            elif health.is_hdd:
                print(f"   ✅ HDD detected — best conditions for recovery")
                print()
            elif health.is_ssd:
                print(f"   ⚠️  SSD detected — recovery may be limited")
                print()
        except Exception as e:
            print(f"   ℹ️  Could not detect drive type: {e}")
            print()

    if args.output:
        output_dir = args.output
    else:
        _desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.isdir(_desktop):
            output_dir = os.path.join(_desktop, "RecoveredFiles")
        else:
            output_dir = os.path.join(os.path.expanduser("~"), "RecoveredFiles")
    os.makedirs(output_dir, exist_ok=True)

    categories = set()
    if args.images:
        categories.add("Image")
    if args.videos:
        categories.add("Video")
    if not categories:
        categories = set(get_all_categories())

    print(f"Device:     {device}")
    print(f"Output:     {output_dir}")
    print(f"Categories: {', '.join(sorted(categories))}")
    print(f"Mode:       {'Preview' if args.preview else 'Full recovery'}")
    print()

    _sys = platform.system()
    if _sys in ("Darwin", "Linux") and os.geteuid() != 0:
        print("⚠️  WARNING: Not running as root.")
        print("   Run: sudo python main.py --cli")
        print()
    elif _sys == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  WARNING: Not running as Administrator.")
                print("   Right-click → Run as Administrator")
                print()
        except Exception:
            pass

    if args.skip_trim_check:
        scanner.set_skip_trim_check(True)

    ll = 0

    def on_progress(p: ScanProgress):
        nonlocal ll
        pct = p.progress_percent
        speed = p.speed_mbps
        eta = p.eta_seconds
        if eta < 60:
            es = f"{eta:.0f}s"
        elif eta < 3600:
            es = f"{eta / 60:.1f}m"
        else:
            es = f"{eta / 3600:.1f}h"
        bw = 30
        filled = int(bw * pct / 100)
        bar = "█" * filled + "░" * (bw - filled)
        line = f"\r  [{bar}] {pct:5.1f}%  {speed:.0f} MB/s  ETA: {es}  Found: {p.files_found}"
        pad = max(0, ll - len(line))
        sys.stdout.write(line + " " * pad)
        sys.stdout.flush()
        ll = len(line)

    scanner.set_progress_callback(on_progress)
    scanner.set_file_found_callback(lambda rf: None)

    print("⚡ Scanning...")
    print()
    start = time.time()
    results = scanner.scan(device, output_dir, categories, preview_only=args.preview)
    elapsed = time.time() - start
    print("\n")

    # Performance stats
    p = scanner.progress
    print("─" * 60)
    perf_parts = []
    perf_parts.append(f"Scan mode: {p.scan_mode}")
    if p.fs_type:
        perf_parts.append(f"Filesystem: {p.fs_type.upper()}")
    if p.using_mmap:
        perf_parts.append("I/O: mmap (high-performance)")
    else:
        perf_parts.append("I/O: buffered reads")
    if p.skipped_empty_bytes > 0:
        perf_parts.append(f"Skipped: {_fmt(p.skipped_empty_bytes)} empty blocks")
    if p.drive_type:
        perf_parts.append(f"Drive: {p.drive_type}")
    if p.trim_enabled:
        perf_parts.append("TRIM: ENABLED ⚠️")
    for part in perf_parts:
        print(f"  {part}")
    print("─" * 60)

    print(f"\n{'=' * 60}")
    print(f"  Done in {elapsed:.1f}s — Found {len(results)} file(s)")
    print(f"{'=' * 60}")

    if results:
        by_ext: dict[str, list] = {}
        total_sz = 0
        damaged_count = 0
        healthy_count = 0
        unknown_count = 0
        for rf in results:
            by_ext.setdefault(rf.extension, []).append(rf)
            total_sz += rf.size
            dmg = getattr(rf, 'damage_report', None)
            if dmg and hasattr(dmg, 'damage_level'):
                level = dmg.damage_level
                if level in ('minor', 'moderate', 'severe', 'fatal'):
                    damaged_count += 1
                elif level == 'healthy':
                    healthy_count += 1
                else:
                    unknown_count += 1
            elif not rf.is_valid:
                damaged_count += 1
            else:
                unknown_count += 1
        print()
        print(f"  {'Ext':7s} {'Count':>6s}  {'Size':>10s}  {'Damaged':>8s}")
        print(f"  {'-'*7} {'-'*6}  {'-'*10}  {'-'*8}")
        for ext in sorted(by_ext):
            files = by_ext[ext]
            ext_dmg = sum(1 for f in files
                          if (getattr(f, 'damage_report', None) and
                              hasattr(f.damage_report, 'damage_level') and
                              f.damage_report.damage_level in ('minor', 'moderate', 'severe', 'fatal'))
                          or not f.is_valid)
            dmg_str = f"⚠️ {ext_dmg}" if ext_dmg > 0 else "✅"
            print(f"    .{ext:5s}  {len(files):4d}    {_fmt(sum(f.size for f in files)):>10s}  {dmg_str:>8s}")
        print(f"\n  Total: {_fmt(total_sz)}")
        # Health summary
        h_parts = []
        if healthy_count > 0:
            h_parts.append(f"✅ {healthy_count} healthy")
        if damaged_count > 0:
            h_parts.append(f"⚠️ {damaged_count} damaged/corrupted")
        if unknown_count > 0:
            h_parts.append(f"❓ {unknown_count} unanalyzed")
        if h_parts:
            print(f"  Health: {' | '.join(h_parts)}")

        # List damaged files individually
        if damaged_count > 0:
            print(f"\n  {'─' * 55}")
            print(f"  ⚠️  Damaged/Corrupted Files ({damaged_count}):")
            print(f"  {'─' * 55}")
            for rf in results:
                dmg = getattr(rf, 'damage_report', None)
                is_dmg = False
                if dmg and hasattr(dmg, 'damage_level'):
                    if dmg.damage_level in ('minor', 'moderate', 'severe', 'fatal'):
                        is_dmg = True
                elif not rf.is_valid:
                    is_dmg = True
                if is_dmg:
                    icon = "❓"
                    level = "corrupted"
                    issues = ""
                    if dmg and hasattr(dmg, 'damage_level'):
                        level = dmg.damage_level
                        icon = {"minor": "⚠️", "moderate": "🟡",
                                "severe": "🔴", "fatal": "💀"}.get(level, "❓")
                        if hasattr(dmg, 'issues') and dmg.issues:
                            issues = f" — {dmg.issues[0]}"
                    repairable = ""
                    if dmg and hasattr(dmg, 'repairable') and dmg.repairable:
                        repairable = " [repairable]"
                    print(f"    {icon} .{rf.extension:5s}  "
                          f"{rf.size_human:>8s}  "
                          f"sector #{rf.sector:,}  "
                          f"{level}{repairable}{issues}")

        if not args.preview:
            print(f"\n  Saved to: {output_dir}")
            import json
            log_path = os.path.join(output_dir, "recovery_log.json")
            with open(log_path, "w") as f:
                json.dump(scanner.get_recovery_log(), f, indent=2, default=str)
            print(f"  Log: {log_path}")
        else:
            print("  (Preview mode — files not saved)")
    print()


def _fmt(n):
    s = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{s:.1f} TB"


def main():
    parser = argparse.ArgumentParser(
        description="Recover deleted photos & videos from raw disk sectors.")
    parser.add_argument("--cli", action="store_true", help="Terminal mode")
    parser.add_argument("-d", "--device", default="", help="Device or mount point")
    parser.add_argument("-o", "--output", default="", help="Output directory")
    parser.add_argument("--images", action="store_true", help="Images only")
    parser.add_argument("--videos", action="store_true", help="Videos only")
    parser.add_argument("--preview", action="store_true", help="Detect without saving")
    parser.add_argument("--force", action="store_true",
                        help="Skip TRIM warning confirmation")
    parser.add_argument("--skip-trim-check", action="store_true",
                        help="Skip SSD/TRIM detection entirely")
    parser.add_argument("--no-elevate", action="store_true",
                        help="Don't auto-request admin privileges")
    args = parser.parse_args()

    # Auto-request admin privileges (required for raw disk access)
    if not args.no_elevate:
        _request_admin_privileges()

    if args.cli:
        cli_mode(args)
    else:
        from app import main as gui
        gui()


if __name__ == "__main__":
    main()
