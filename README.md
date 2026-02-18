# 📸 Deleted Photo & Video Recovery

Recover **deleted photos and videos** from raw disk sectors using binary file-signature carving.

**Never** lists, scans, or touches existing files or folders.

---

## How It Works

1. Opens the raw block device in **read-only** mode
2. Reads 4 MB chunks, searching every byte position for known file signatures
3. **JPEG/PNG**: Matches header bytes → searches for footer marker → carves exact file
4. **MP4/MOV/HEIC**: Searches for `ftyp` pattern, checks brand string, walks ISO Base Media box structure to determine exact file size
5. Validates recovered data (structural checks + Shannon entropy)
6. Deduplicates by content hash
7. Saves as `recovered_000001.jpg`, etc.

### Why This Version Works (Previous Didn't)

| Problem in v1 | Fix in v2 |
|---|---|
| Hard-coded ftyp box sizes (`\x00\x00\x00\x18 ftyp isom`) — missed 95% of real MP4/MOV/HEIC files | Search for `ftyp` at byte +4, then check brand — catches ALL ftyp variants |
| Stepped by 512-byte sectors — missed headers not on sector boundaries | Uses `bytes.find()` to locate ALL occurrences within each chunk |
| `MAX_ENTROPY = 7.99` — rejected valid compressed JPEGs | Raised to `7.9999`, sample from middle of file not just header |
| Footer not found → used `max_size / 10` (arbitrary) | Search full `max_size` for footer, accept truncated files |
| Searched for ~22 rigid byte patterns | 2 header patterns (JPEG, PNG) + 1 flexible `ftyp` search covering 60+ brands |

---

## Supported Formats

| Type | Extensions | Detection Method |
|---|---|---|
| JPEG | `.jpg` | Header `FF D8 FF` → Footer `FF D9` |
| PNG | `.png` | Header `89 50 4E 47` → Footer `IEND` chunk |
| HEIC | `.heic` | `ftyp` box with brand `heic`/`mif1`/`heix`/etc. |
| MP4 | `.mp4` | `ftyp` box with brand `isom`/`mp42`/`avc1`/`3gp5`/etc. (40+ brands) |
| MOV | `.mov` | `ftyp` box with brand `qt  `/`MQT ` |

---

## Usage

### GUI
```bash
sudo python main.py
```

### CLI
```bash
sudo python main.py --cli                      # Interactive drive selection
sudo python main.py --cli -d /Volumes/MyUSB    # Specific drive
sudo python main.py --cli -d /dev/disk4 --images   # Photos only
sudo python main.py --cli -d disk.img --preview     # Dry run on disk image
```

### Options
| Flag | Description |
|---|---|
| `--cli` | Terminal mode |
| `-d` | Device / mount point / disk image |
| `-o` | Output directory (default: `~/Desktop/RecoveredFiles`) |
| `--images` | Photos only |
| `--videos` | Videos only |
| `--preview` | Detect without saving |

---

## Project Structure

```
main.py                CLI + GUI entry point
app.py                 Tkinter GUI
recovery/
  signatures.py        Flexible signature database (header patterns + ftyp brands)
  scanner.py           Raw binary carving engine (bytes.find based)
  manager.py           Scan orchestration, saving, reports
  smart_filter.py      Entropy validation, structural checks, dedup
```

---

## Requirements

- Python 3.10+
- No third-party packages (stdlib only)
- Root / Administrator for raw disk access

---

## Safety

- Source drive opened **read-only**
- No writes to source
- Min file size 4 KB (filters garbage)
- Entropy analysis prevents saving empty/corrupt blocks
- MD5 deduplication

## License

MIT
