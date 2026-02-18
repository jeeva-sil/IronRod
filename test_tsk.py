#!/usr/bin/env python3
"""Quick test of pytsk3 on the USB device."""
import pytsk3
import sys
import time
import threading

def _start_timeout(seconds: int = 30):
    """Cross-platform timeout — works on Windows, Linux, and macOS."""
    def _watchdog():
        print("TIMEOUT — TSK took too long")
        import os
        os._exit(1)
    timer = threading.Timer(seconds, _watchdog)
    timer.daemon = True
    timer.start()
    return timer

_timer = _start_timeout(30)

device = "/dev/rdisk2s1"
print(f"Opening {device}...")

try:
    t0 = time.time()
    img = pytsk3.Img_Info(device)
    print(f"  Img_Info OK in {time.time()-t0:.2f}s")

    t0 = time.time()
    fs = pytsk3.FS_Info(img)
    print(f"  FS_Info OK in {time.time()-t0:.2f}s, ftype={fs.info.ftype}, block_size={fs.info.block_size}")

    t0 = time.time()
    root = fs.open_dir("/")
    print(f"  Root dir opened in {time.time()-t0:.2f}s")

    count = 0
    deleted = 0
    t0 = time.time()

    for entry in root:
        count += 1
        meta = entry.info.meta
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")

        if meta:
            is_del = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC) or \
                     bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            if is_del:
                deleted += 1
                if deleted <= 30:
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    print(f"  DELETED: {name}  size={meta.size}  ext={ext}")

        if count > 2000:
            print(f"  ... stopping at {count} entries")
            break

    elapsed = time.time() - t0
    print(f"\nRoot dir: {count} entries, {deleted} deleted in {elapsed:.2f}s")

except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")

_timer.cancel()
print("Done")
