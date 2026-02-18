# recovery — Deleted Photo & Video Recovery Engine
# Pure-Python raw binary file carving from disk sectors.
#
# Architecture (bottom → top):
#   mmap_reader    — High-performance mmap I/O + empty block skipping
#   trim_detect    — SSD/TRIM pre-flight check (abort if recovery impossible)
#   filesystem     — Parse exFAT/FAT32/NTFS allocation bitmaps
#   signatures     — File type database (JPEG, PNG, HEIC, MP4, MOV)
#   smart_filter   — Validation + deduplication for carved files
#   scanner        — Core carving engine (raw sector scan)
#   parallel       — Multiprocessing support for partition-based scanning
#   manager        — Orchestrator (threading, save, export)
