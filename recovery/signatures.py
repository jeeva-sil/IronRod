"""
File Signature Database — ALL Image & Video Recovery.

DESIGN RATIONALE
────────────────
Comprehensive file carving signature database covering:
  • Fixed-header formats (JPEG, PNG, GIF, BMP, TIFF, PSD, TGA, ICO, JP2)
  • RIFF-based formats  (WebP, AVI) — header = RIFF + sub-type at offset 8
  • EBML-based formats  (MKV, WebM) — Matroska / WebM containers
  • ISO Base Media      (MP4, MOV, HEIC, AVIF, 3GP, M4V) — ftyp brand matching
  • Other video formats (FLV, WMV/ASF, MPEG-PS, MPEG-TS, OGG/OGV, VOB)
  • RAW camera formats  (CR2, NEF, ARW, DNG, ORF, RW2, RAF) — TIFF-based + extras

Exported for the scanner:
  • HEADER_SIGNATURES  — list of (header_bytes, SignatureInfo) for fixed-header formats
  • RIFF_TYPES         — dict mapping RIFF sub-type → SignatureInfo
  • FTYP_BRANDS        — dict mapping ftyp brand → SignatureInfo
  • SignatureInfo       — lightweight dataclass describing a file type
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SignatureInfo:
    """Describes one recoverable file type."""
    category: str               # "Image" or "Video"
    extension: str              # file extension without dot
    description: str
    footer: Optional[bytes] = None      # End-of-file marker (JPEG, PNG, GIF)
    max_size: int = 50 * 1024 * 1024    # Reasonable upper cap
    min_size: int = 4 * 1024            # 4 KB minimum
    # How the scanner determines file size:
    #   "footer"     — search for footer marker (JPEG, PNG, GIF)
    #   "header"     — size encoded in the file header (BMP, RIFF, EBML)
    #   "isobmff"    — walk ISO box structure (MP4, MOV, HEIC)
    #   "maxread"    — read up to max_size (TIFF, PSD, RAW, etc.)
    carve_mode: str = "footer"


# ══════════════════════════════════════════════════════════════
#  I M A G E   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── JPEG ──
SIG_JPEG = SignatureInfo(
    category="Image", extension="jpg", description="JPEG Image",
    footer=b"\xFF\xD9",
    max_size=30 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="footer",
)

# ── PNG ──
SIG_PNG = SignatureInfo(
    category="Image", extension="png", description="PNG Image",
    footer=b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82",
    max_size=30 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="footer",
)

# ── GIF ──
SIG_GIF = SignatureInfo(
    category="Image", extension="gif", description="GIF Image",
    footer=b"\x00\x3B",
    max_size=30 * 1024 * 1024, min_size=1024,
    carve_mode="footer",
)

# ── BMP ──  (file size at offset 2, 4-byte LE)
SIG_BMP = SignatureInfo(
    category="Image", extension="bmp", description="BMP Image",
    max_size=100 * 1024 * 1024, min_size=1024,
    carve_mode="header",
)

# ── TIFF (little-endian) ──
SIG_TIFF_LE = SignatureInfo(
    category="Image", extension="tiff", description="TIFF Image (LE)",
    max_size=200 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── TIFF (big-endian) ──
SIG_TIFF_BE = SignatureInfo(
    category="Image", extension="tiff", description="TIFF Image (BE)",
    max_size=200 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── WebP ──  (RIFF container)
SIG_WEBP = SignatureInfo(
    category="Image", extension="webp", description="WebP Image",
    max_size=30 * 1024 * 1024, min_size=1024,
    carve_mode="header",   # size from RIFF header
)

# ── JPEG 2000 ──
SIG_JP2 = SignatureInfo(
    category="Image", extension="jp2", description="JPEG 2000 Image",
    max_size=50 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── PSD (Photoshop) ──
SIG_PSD = SignatureInfo(
    category="Image", extension="psd", description="Adobe Photoshop Document",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── ICO ──
SIG_ICO = SignatureInfo(
    category="Image", extension="ico", description="Windows Icon",
    max_size=1 * 1024 * 1024, min_size=256,
    carve_mode="header",
)

# ── TGA (footer-based detection) ──
SIG_TGA = SignatureInfo(
    category="Image", extension="tga", description="Targa Image",
    max_size=100 * 1024 * 1024, min_size=1024,
    carve_mode="maxread",
)

# ── HEIC / HEIF / AVIF ──  (ISO Base Media)
SIG_HEIC = SignatureInfo(
    category="Image", extension="heic", description="HEIC Image",
    max_size=80 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="isobmff",
)

SIG_AVIF = SignatureInfo(
    category="Image", extension="avif", description="AVIF Image",
    max_size=80 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="isobmff",
)

# ── RAW Camera Formats (all TIFF-based, carve as maxread) ──
SIG_CR2 = SignatureInfo(
    category="Image", extension="cr2", description="Canon RAW (CR2)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_NEF = SignatureInfo(
    category="Image", extension="nef", description="Nikon RAW (NEF)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_ARW = SignatureInfo(
    category="Image", extension="arw", description="Sony RAW (ARW)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_DNG = SignatureInfo(
    category="Image", extension="dng", description="Adobe DNG RAW",
    max_size=200 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_ORF = SignatureInfo(
    category="Image", extension="orf", description="Olympus RAW (ORF)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_RW2 = SignatureInfo(
    category="Image", extension="rw2", description="Panasonic RAW (RW2)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

SIG_RAF = SignatureInfo(
    category="Image", extension="raf", description="Fujifilm RAW (RAF)",
    max_size=80 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  V I D E O   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── MP4 ──  (ISO Base Media)
SIG_MP4 = SignatureInfo(
    category="Video", extension="mp4", description="MP4 Video",
    max_size=8 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="isobmff",
)

# ── MOV ──  (ISO Base Media / QuickTime)
SIG_MOV = SignatureInfo(
    category="Video", extension="mov", description="MOV Video (QuickTime)",
    max_size=8 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="isobmff",
)

# ── 3GP ──  (ISO Base Media)
SIG_3GP = SignatureInfo(
    category="Video", extension="3gp", description="3GP Video",
    max_size=2 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="isobmff",
)

# ── M4V ──  (ISO Base Media)
SIG_M4V = SignatureInfo(
    category="Video", extension="m4v", description="M4V Video (iTunes)",
    max_size=8 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="isobmff",
)

# ── AVI ──  (RIFF container)
SIG_AVI = SignatureInfo(
    category="Video", extension="avi", description="AVI Video",
    max_size=4 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="header",   # size from RIFF header
)

# ── MKV ──  (Matroska / EBML)
SIG_MKV = SignatureInfo(
    category="Video", extension="mkv", description="MKV Video (Matroska)",
    max_size=8 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

# ── WebM ──  (Matroska / EBML subset)
SIG_WEBM = SignatureInfo(
    category="Video", extension="webm", description="WebM Video",
    max_size=4 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

# ── FLV ──
SIG_FLV = SignatureInfo(
    category="Video", extension="flv", description="Flash Video (FLV)",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── WMV / ASF ──
SIG_WMV = SignatureInfo(
    category="Video", extension="wmv", description="Windows Media Video",
    max_size=4 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

# ── MPEG Program Stream ──
# MPEG-PS end code 0x000001B9 marks end of stream.
SIG_MPG = SignatureInfo(
    category="Video", extension="mpg", description="MPEG Video",
    footer=b"\x00\x00\x01\xB9",
    max_size=4 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="footer",
)

# ── MPEG Transport Stream ──
SIG_TS = SignatureInfo(
    category="Video", extension="ts", description="MPEG Transport Stream",
    max_size=4 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

# ── VOB (DVD Video) ──
SIG_VOB = SignatureInfo(
    category="Video", extension="vob", description="DVD Video Object",
    max_size=2 * 1024 * 1024 * 1024, min_size=8 * 1024,
    carve_mode="maxread",
)

# ── OGG / OGV ──
SIG_OGV = SignatureInfo(
    category="Video", extension="ogv", description="OGG Video",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── RealMedia ──
SIG_RM = SignatureInfo(
    category="Video", extension="rm", description="RealMedia Video",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── SWF (Flash) ──
SIG_SWF = SignatureInfo(
    category="Video", extension="swf", description="Flash Animation (SWF)",
    max_size=200 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  A U D I O   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── MP3 ──
# ID3v2 header (most modern MP3s) or MPEG audio frame sync (0xFF 0xFB/FA/F3/F2)
SIG_MP3 = SignatureInfo(
    category="Audio", extension="mp3", description="MP3 Audio",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── WAV ──  (RIFF container with WAVE sub-type)
SIG_WAV = SignatureInfo(
    category="Audio", extension="wav", description="WAV Audio",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="header",   # size from RIFF header
)

# ── FLAC ──
SIG_FLAC = SignatureInfo(
    category="Audio", extension="flac", description="FLAC Audio (Lossless)",
    max_size=1 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── AAC / M4A ──  (ISO Base Media container)
SIG_M4A = SignatureInfo(
    category="Audio", extension="m4a", description="AAC/M4A Audio",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="isobmff",
)

# ── OGG Audio ──  (Vorbis/Opus in OGG container)
SIG_OGA = SignatureInfo(
    category="Audio", extension="ogg", description="OGG Audio (Vorbis/Opus)",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── WMA ──  (ASF container — same header as WMV, distinguished by content)
SIG_WMA = SignatureInfo(
    category="Audio", extension="wma", description="Windows Media Audio",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── AIFF ──
SIG_AIFF = SignatureInfo(
    category="Audio", extension="aiff", description="AIFF Audio",
    max_size=2 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="header",  # FORM header has size like RIFF
)

# ── MIDI ──
SIG_MIDI = SignatureInfo(
    category="Audio", extension="mid", description="MIDI Sequence",
    max_size=10 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  D O C U M E N T   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── PDF ──
SIG_PDF = SignatureInfo(
    category="Document", extension="pdf", description="PDF Document",
    footer=b"%%EOF",
    max_size=2 * 1024 * 1024 * 1024, min_size=1024,
    carve_mode="footer",
)

# ── ZIP / DOCX / XLSX / PPTX / JAR / APK ──
SIG_ZIP = SignatureInfo(
    category="Document", extension="zip", description="ZIP Archive",
    max_size=4 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── DOCX ── (ZIP with specific content)
SIG_DOCX = SignatureInfo(
    category="Document", extension="docx", description="Word Document (DOCX)",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)

# ── XLSX ──
SIG_XLSX = SignatureInfo(
    category="Document", extension="xlsx", description="Excel Spreadsheet (XLSX)",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)

# ── PPTX ──
SIG_PPTX = SignatureInfo(
    category="Document", extension="pptx", description="PowerPoint (PPTX)",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)

# ── SQLite ──
SIG_SQLITE = SignatureInfo(
    category="Document", extension="sqlite", description="SQLite Database",
    max_size=4 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── RTF ──
SIG_RTF = SignatureInfo(
    category="Document", extension="rtf", description="Rich Text Format",
    footer=b"}",
    max_size=200 * 1024 * 1024, min_size=256,
    carve_mode="footer",
)

# ── XML ──
SIG_XML = SignatureInfo(
    category="Document", extension="xml", description="XML Document",
    max_size=500 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── HTML ──
SIG_HTML = SignatureInfo(
    category="Document", extension="html", description="HTML Document",
    max_size=100 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── EPUB ──  (ZIP-based e-book)
SIG_EPUB = SignatureInfo(
    category="Document", extension="epub", description="EPUB E-Book",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)

# ── ODP/ODS/ODT ──  (OpenDocument, ZIP-based)
SIG_ODT = SignatureInfo(
    category="Document", extension="odt", description="OpenDocument Text",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)
SIG_ODS = SignatureInfo(
    category="Document", extension="ods", description="OpenDocument Spreadsheet",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)
SIG_ODP = SignatureInfo(
    category="Document", extension="odp", description="OpenDocument Presentation",
    max_size=500 * 1024 * 1024, min_size=2 * 1024,
    carve_mode="maxread",
)

# ── EPS ──
SIG_EPS = SignatureInfo(
    category="Document", extension="eps", description="Encapsulated PostScript",
    max_size=200 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── CSV ──  (detected by UTF-8 BOM or heuristic; limited recovery value)
SIG_CSV = SignatureInfo(
    category="Document", extension="csv", description="CSV Data File",
    max_size=500 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Microsoft Compound Binary (DOC/XLS/PPT/MSG) ──
SIG_DOC_OLE = SignatureInfo(
    category="Document", extension="doc", description="MS Office Document (OLE)",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  A R C H I V E   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── 7-Zip ──
SIG_7Z = SignatureInfo(
    category="Archive", extension="7z", description="7-Zip Archive",
    max_size=4 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── RAR ──
SIG_RAR = SignatureInfo(
    category="Archive", extension="rar", description="RAR Archive",
    max_size=4 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── GZIP ──
SIG_GZ = SignatureInfo(
    category="Archive", extension="gz", description="GZIP Compressed",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── BZIP2 ──
SIG_BZ2 = SignatureInfo(
    category="Archive", extension="bz2", description="BZIP2 Compressed",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── XZ ──
SIG_XZ = SignatureInfo(
    category="Archive", extension="xz", description="XZ Compressed",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── TAR ──  (detected by "ustar" at offset 257)
SIG_TAR = SignatureInfo(
    category="Archive", extension="tar", description="TAR Archive",
    max_size=4 * 1024 * 1024 * 1024, min_size=1024,
    carve_mode="maxread",
)

# ── CAB ──  (Microsoft Cabinet)
SIG_CAB = SignatureInfo(
    category="Archive", extension="cab", description="Microsoft Cabinet",
    max_size=2 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="header",
)

# ── ISO 9660 Disc Image ──
SIG_ISO = SignatureInfo(
    category="Archive", extension="iso", description="ISO 9660 Disc Image",
    max_size=8 * 1024 * 1024 * 1024, min_size=32 * 1024,
    carve_mode="maxread",
)

# ── DMG (Apple Disk Image) ──
SIG_DMG = SignatureInfo(
    category="Archive", extension="dmg", description="Apple Disk Image",
    max_size=8 * 1024 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── ZSTD ──
SIG_ZSTD = SignatureInfo(
    category="Archive", extension="zst", description="Zstandard Compressed",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── LZ4 ──
SIG_LZ4 = SignatureInfo(
    category="Archive", extension="lz4", description="LZ4 Compressed",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  E X E C U T A B L E   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── PE (EXE/DLL/SYS) ──
SIG_EXE = SignatureInfo(
    category="Executable", extension="exe", description="Windows Executable (PE)",
    max_size=2 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── ELF (Linux executables, shared objects) ──
SIG_ELF = SignatureInfo(
    category="Executable", extension="elf", description="ELF Binary (Linux)",
    max_size=2 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Mach-O (macOS binaries) ──
SIG_MACHO = SignatureInfo(
    category="Executable", extension="macho", description="Mach-O Binary (macOS)",
    max_size=2 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Mach-O Fat/Universal Binary ──
SIG_MACHO_FAT = SignatureInfo(
    category="Executable", extension="macho", description="Mach-O Universal Binary",
    max_size=2 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── DEX (Android Dalvik Executable) ──
SIG_DEX = SignatureInfo(
    category="Executable", extension="dex", description="Android DEX Bytecode",
    max_size=200 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── Java CLASS ──
SIG_CLASS = SignatureInfo(
    category="Executable", extension="class", description="Java Class File",
    max_size=50 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── WebAssembly ──
SIG_WASM = SignatureInfo(
    category="Executable", extension="wasm", description="WebAssembly Binary",
    max_size=200 * 1024 * 1024, min_size=8,
    carve_mode="maxread",
)

# ── Python Compiled (.pyc) ──
SIG_PYC = SignatureInfo(
    category="Executable", extension="pyc", description="Python Compiled Bytecode",
    max_size=50 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  F O N T   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── TrueType / OpenType ──
SIG_TTF = SignatureInfo(
    category="Font", extension="ttf", description="TrueType Font",
    max_size=50 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

SIG_OTF = SignatureInfo(
    category="Font", extension="otf", description="OpenType Font",
    max_size=50 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── WOFF / WOFF2 (Web Fonts) ──
SIG_WOFF = SignatureInfo(
    category="Font", extension="woff", description="WOFF Web Font",
    max_size=50 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

SIG_WOFF2 = SignatureInfo(
    category="Font", extension="woff2", description="WOFF2 Web Font",
    max_size=50 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  D A T A B A S E / S C I E N C E   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── Apache Parquet ──
SIG_PARQUET = SignatureInfo(
    category="Database", extension="parquet", description="Apache Parquet Data",
    footer=b"PAR1",
    max_size=4 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── Apache Avro ──
SIG_AVRO = SignatureInfo(
    category="Database", extension="avro", description="Apache Avro Data",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Apache ORC ──
SIG_ORC = SignatureInfo(
    category="Database", extension="orc", description="Apache ORC Data",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── HDF5 ──
SIG_HDF5 = SignatureInfo(
    category="Database", extension="hdf5", description="HDF5 Scientific Data",
    max_size=8 * 1024 * 1024 * 1024, min_size=256,
    carve_mode="maxread",
)

# ── NumPy Array (.npy) ──
SIG_NPY = SignatureInfo(
    category="Database", extension="npy", description="NumPy Array",
    max_size=4 * 1024 * 1024 * 1024, min_size=128,
    carve_mode="maxread",
)

# ── Protocol Buffers Compiled ──
# (not easily detectable from header alone; skip for now)

# ── PCAP (Network Capture) ──
SIG_PCAP = SignatureInfo(
    category="Database", extension="pcap", description="Network Packet Capture",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── PCAPNG (Next-Gen Network Capture) ──
SIG_PCAPNG = SignatureInfo(
    category="Database", extension="pcapng", description="PCAP-NG Network Capture",
    max_size=4 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)


# ══════════════════════════════════════════════════════════════
#  M I S C E L L A N E O U S   S I G N A T U R E S
# ══════════════════════════════════════════════════════════════

# ── SVG (Scalable Vector Graphics) ──
SIG_SVG = SignatureInfo(
    category="Image", extension="svg", description="SVG Vector Image",
    max_size=100 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Windows Shortcut (LNK) ──
SIG_LNK = SignatureInfo(
    category="System", extension="lnk", description="Windows Shortcut",
    max_size=1 * 1024 * 1024, min_size=128,
    carve_mode="maxread",
)

# ── Windows Registry Hive ──
SIG_REG = SignatureInfo(
    category="System", extension="reg", description="Windows Registry Hive",
    max_size=500 * 1024 * 1024, min_size=4 * 1024,
    carve_mode="maxread",
)

# ── GPG/PGP Encrypted ──
SIG_GPG = SignatureInfo(
    category="System", extension="gpg", description="GPG/PGP Encrypted Data",
    max_size=2 * 1024 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── Bitcoin Wallet ──
# (uses Berkeley DB format — not easily distinguishable; skip for now)

# ── Apple Property List (binary plist) ──
SIG_PLIST = SignatureInfo(
    category="System", extension="plist", description="Apple Binary Property List",
    max_size=50 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)

# ── ASN.1 / DER Certificate ──
SIG_DER = SignatureInfo(
    category="System", extension="der", description="DER Certificate / Key",
    max_size=10 * 1024 * 1024, min_size=64,
    carve_mode="maxread",
)


# ═════════════════════════════════════════════════════════════
#  HEADER_SIGNATURES — Fixed magic bytes at offset 0
# ═════════════════════════════════════════════════════════════
# Sorted longest-first by the scanner for priority matching.

HEADER_SIGNATURES: list[tuple[bytes, SignatureInfo]] = [
    # ── Images ──
    (b"\xFF\xD8\xFF",                   SIG_JPEG),
    (b"\x89PNG\r\n\x1A\n",             SIG_PNG),
    (b"GIF89a",                         SIG_GIF),
    (b"GIF87a",                         SIG_GIF),
    (b"BM",                             SIG_BMP),
    (b"II\x2A\x00",                     SIG_TIFF_LE),     # TIFF little-endian
    (b"MM\x00\x2A",                     SIG_TIFF_BE),     # TIFF big-endian
    (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A", SIG_JP2),  # JPEG 2000
    (b"8BPS",                           SIG_PSD),
    (b"\x00\x00\x01\x00",              SIG_ICO),
    (b"FUJIFILMCCD-RAW",               SIG_RAF),          # Fujifilm RAW

    # ── Videos ──
    (b"\x1A\x45\xDF\xA3",             SIG_MKV),          # EBML (MKV/WebM) — refined by doctype
    (b"FLV\x01",                        SIG_FLV),
    (b"\x30\x26\xB2\x75\x8E\x66\xCF\x11", SIG_WMV),     # ASF/WMV header GUID
    (b"\x00\x00\x01\xBA",             SIG_MPG),           # MPEG Program Stream
    (b"\x00\x00\x01\xB3",             SIG_MPG),           # MPEG-1 sequence header
    (b"\x00\x00\x01\xBB",             SIG_MPG),           # MPEG system header
    (b"\x00\x00\x01\xB8",             SIG_MPG),           # MPEG GOP header
    (b"OggS",                           SIG_OGV),          # OGG container
    (b".RMF",                           SIG_RM),           # RealMedia
    (b"FWS",                            SIG_SWF),          # Uncompressed SWF
    (b"CWS",                            SIG_SWF),          # Compressed SWF (zlib)

    # ── Audio ──
    (b"ID3",                            SIG_MP3),          # MP3 with ID3v2 tag
    (b"\xFF\xFB",                       SIG_MP3),          # MPEG Audio Layer 3 (sync + MPEG1 L3)
    (b"\xFF\xFA",                       SIG_MP3),          # MPEG Audio Layer 3 (sync + MPEG1 L3 CRC)
    (b"\xFF\xF3",                       SIG_MP3),          # MPEG Audio Layer 3 (MPEG2)
    (b"\xFF\xF2",                       SIG_MP3),          # MPEG Audio Layer 3 (MPEG2 CRC)
    (b"fLaC",                           SIG_FLAC),         # FLAC
    (b"FORM",                           SIG_AIFF),         # AIFF (FORM + AIFF sub-type)
    (b"MThd",                           SIG_MIDI),         # MIDI

    # ── Documents ──
    (b"%PDF",                           SIG_PDF),          # PDF
    (b"PK\x03\x04",                    SIG_ZIP),          # ZIP / DOCX / XLSX / PPTX
    (b"SQLite format 3\x00",           SIG_SQLITE),       # SQLite
    (b"{\\rtf",                         SIG_RTF),          # RTF
    (b"<?xml",                          SIG_XML),          # XML
    (b"\xEF\xBB\xBF<?xml",            SIG_XML),          # XML with BOM
    (b"<!DOCTYPE",                      SIG_HTML),         # HTML doctype
    (b"<html",                          SIG_HTML),         # HTML
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", SIG_DOC_OLE), # MS OLE2 (DOC/XLS/PPT/MSG)
    (b"%!PS-Adobe",                    SIG_EPS),          # EPS PostScript

    # ── Archives ──
    (b"7z\xBC\xAF\x27\x1C",           SIG_7Z),           # 7-Zip
    (b"Rar!\x1A\x07\x01\x00",         SIG_RAR),          # RAR5
    (b"Rar!\x1A\x07\x00",             SIG_RAR),          # RAR4
    (b"\x1F\x8B",                       SIG_GZ),           # GZIP
    (b"BZh",                            SIG_BZ2),          # BZIP2
    (b"\xFD\x37\x7A\x58\x5A\x00",     SIG_XZ),           # XZ
    (b"MSCF",                           SIG_CAB),          # CAB
    (b"\x28\xB5\x2F\xFD",             SIG_ZSTD),         # Zstandard
    (b"\x04\x22\x4D\x18",             SIG_LZ4),          # LZ4

    # ── Executables ──
    (b"MZ",                             SIG_EXE),          # PE (EXE/DLL)
    (b"\x7FELF",                        SIG_ELF),          # ELF binary
    (b"\xFE\xED\xFA\xCE",             SIG_MACHO),        # Mach-O 32-bit
    (b"\xFE\xED\xFA\xCF",             SIG_MACHO),        # Mach-O 64-bit
    (b"\xCE\xFA\xED\xFE",             SIG_MACHO),        # Mach-O 32-bit (reversed)
    (b"\xCF\xFA\xED\xFE",             SIG_MACHO),        # Mach-O 64-bit (reversed)
    (b"\xCA\xFE\xBA\xBE",             SIG_MACHO_FAT),    # Mach-O Fat/Universal
    (b"dex\n",                          SIG_DEX),          # Android DEX
    (b"\xCA\xFE\xBA\xBE",             SIG_CLASS),         # Java CLASS (overlaps Fat Mach-O)
    (b"\x00asm",                        SIG_WASM),         # WebAssembly

    # ── Fonts ──
    (b"\x00\x01\x00\x00",              SIG_TTF),          # TrueType
    (b"OTTO",                           SIG_OTF),          # OpenType with CFF
    (b"wOFF",                           SIG_WOFF),         # WOFF
    (b"wOF2",                           SIG_WOFF2),        # WOFF2
    (b"true",                           SIG_TTF),          # TrueType (alternate)

    # ── Data/Science ──
    (b"PAR1",                           SIG_PARQUET),      # Apache Parquet
    (b"Obj\x01",                        SIG_AVRO),         # Apache Avro
    (b"ORC",                            SIG_ORC),          # Apache ORC
    (b"\x89HDF\r\n\x1A\n",            SIG_HDF5),         # HDF5
    (b"\x93NUMPY",                      SIG_NPY),          # NumPy .npy
    (b"\xD4\xC3\xB2\xA1",             SIG_PCAP),         # PCAP (little-endian)
    (b"\xA1\xB2\xC3\xD4",             SIG_PCAP),         # PCAP (big-endian)
    (b"\x0A\x0D\x0D\x0A",             SIG_PCAPNG),       # PCAP-NG

    # ── System / Misc ──
    (b"\x4C\x00\x00\x00\x01\x14\x02\x00", SIG_LNK),      # Windows LNK shortcut
    (b"regf",                           SIG_REG),          # Windows Registry Hive
    (b"bplist",                         SIG_PLIST),        # Apple binary plist
]


# ═════════════════════════════════════════════════════════════
#  RIFF-based formats — header "RIFF" + sub-type at offset 8
# ═════════════════════════════════════════════════════════════
# The scanner searches for b"RIFF" at offset 0, then reads the
# 4-byte sub-type at offset 8 to distinguish WebP vs AVI.

RIFF_TYPES: dict[bytes, SignatureInfo] = {
    b"WEBP": SIG_WEBP,
    b"AVI ": SIG_AVI,
    b"WAVE": SIG_WAV,
}


# ═════════════════════════════════════════════════════════════
#  ISO Base Media — ftyp brand → SignatureInfo
# ═════════════════════════════════════════════════════════════
# The scanner searches for b"ftyp" at offset +4, reads the
# 4-byte major brand to determine the type.

FTYP_BRANDS: dict[bytes, SignatureInfo] = {
    # HEIC / HEIF
    b"heic": SIG_HEIC,
    b"heix": SIG_HEIC,
    b"hevc": SIG_HEIC,
    b"hevx": SIG_HEIC,
    b"mif1": SIG_HEIC,
    b"msf1": SIG_HEIC,
    b"heis": SIG_HEIC,

    # AVIF (separate extension)
    b"avif": SIG_AVIF,
    b"avis": SIG_AVIF,

    # MP4
    b"isom": SIG_MP4,
    b"iso2": SIG_MP4,
    b"iso3": SIG_MP4,
    b"iso4": SIG_MP4,
    b"iso5": SIG_MP4,
    b"iso6": SIG_MP4,
    b"mp41": SIG_MP4,
    b"mp42": SIG_MP4,
    b"mp71": SIG_MP4,
    b"avc1": SIG_MP4,
    b"MSNV": SIG_MP4,
    b"NDAS": SIG_MP4,
    b"NDSC": SIG_MP4,
    b"NDSH": SIG_MP4,
    b"NDSM": SIG_MP4,
    b"NDSP": SIG_MP4,
    b"NDSS": SIG_MP4,
    b"NDXH": SIG_MP4,
    b"NDXM": SIG_MP4,
    b"NDXP": SIG_MP4,
    b"NDXS": SIG_MP4,
    b"dash": SIG_MP4,
    b"F4V ": SIG_MP4,

    # MOV / QuickTime
    b"qt  ": SIG_MOV,
    b"MQT ": SIG_MOV,

    # M4V
    b"M4V ": SIG_M4V,
    b"M4VH": SIG_M4V,
    b"M4VP": SIG_M4V,

    # 3GP
    b"3gp4": SIG_3GP,
    b"3gp5": SIG_3GP,
    b"3gp6": SIG_3GP,
    b"3gp7": SIG_3GP,
    b"3gs7": SIG_3GP,
    b"3ge6": SIG_3GP,
    b"3ge7": SIG_3GP,
    b"3gg6": SIG_3GP,
    b"3g2a": SIG_3GP,
    b"3g2b": SIG_3GP,
    b"3g2c": SIG_3GP,

    # M4A / AAC Audio
    b"M4A ": SIG_M4A,
    b"M4B ": SIG_M4A,   # M4B audiobook
    b"mp4a": SIG_M4A,
}

# Also accept "mp4" variants like "mp40" .. "mp49"
for _v in range(10):
    _key = b"mp4" + bytes([0x30 + _v])
    if _key not in FTYP_BRANDS:
        FTYP_BRANDS[_key] = SIG_MP4

# Exact 3-char brands padded with space
for _brand in (b"mp4 ", b"MP4 ", b"mov ", b"MOV "):
    if _brand not in FTYP_BRANDS:
        FTYP_BRANDS[_brand] = SIG_MP4 if b"mp4" in _brand.lower() else SIG_MOV


# ═════════════════════════════════════════════════════════════
#  MPEG-TS detection helper
# ═════════════════════════════════════════════════════════════
# MPEG-TS uses 0x47 sync byte every 188 bytes.  The scanner calls
# is_mpeg_ts() to confirm 3+ consecutive sync bytes before carving.

TS_PACKET_SIZE = 188

def is_mpeg_ts(data: bytes, offset: int = 0) -> bool:
    """Check for 4 consecutive MPEG-TS sync bytes at 188-byte intervals."""
    for i in range(4):
        pos = offset + i * TS_PACKET_SIZE
        if pos >= len(data) or data[pos] != 0x47:
            return False
    return True


# ═════════════════════════════════════════════════════════════
#  Convenience helpers
# ═════════════════════════════════════════════════════════════

ALL_SIGNATURES: list[SignatureInfo] = [
    # Images
    SIG_JPEG, SIG_PNG, SIG_GIF, SIG_BMP,
    SIG_TIFF_LE, SIG_TIFF_BE, SIG_WEBP, SIG_JP2,
    SIG_PSD, SIG_ICO, SIG_TGA, SIG_SVG,
    SIG_HEIC, SIG_AVIF,
    SIG_CR2, SIG_NEF, SIG_ARW, SIG_DNG, SIG_ORF, SIG_RW2, SIG_RAF,
    # Videos
    SIG_MP4, SIG_MOV, SIG_3GP, SIG_M4V,
    SIG_AVI, SIG_MKV, SIG_WEBM, SIG_FLV,
    SIG_WMV, SIG_MPG, SIG_TS, SIG_VOB,
    SIG_OGV, SIG_RM, SIG_SWF,
    # Audio
    SIG_MP3, SIG_WAV, SIG_FLAC, SIG_M4A, SIG_OGA,
    SIG_WMA, SIG_AIFF, SIG_MIDI,
    # Documents
    SIG_PDF, SIG_ZIP, SIG_DOCX, SIG_XLSX, SIG_PPTX, SIG_SQLITE,
    SIG_RTF, SIG_XML, SIG_HTML, SIG_EPUB,
    SIG_ODT, SIG_ODS, SIG_ODP,
    SIG_EPS, SIG_CSV, SIG_DOC_OLE,
    # Archives
    SIG_7Z, SIG_RAR, SIG_GZ, SIG_BZ2, SIG_XZ,
    SIG_TAR, SIG_CAB, SIG_ISO, SIG_DMG,
    SIG_ZSTD, SIG_LZ4,
    # Executables
    SIG_EXE, SIG_ELF, SIG_MACHO, SIG_MACHO_FAT,
    SIG_DEX, SIG_CLASS, SIG_WASM, SIG_PYC,
    # Fonts
    SIG_TTF, SIG_OTF, SIG_WOFF, SIG_WOFF2,
    # Database / Data Science
    SIG_PARQUET, SIG_AVRO, SIG_ORC, SIG_HDF5, SIG_NPY,
    SIG_PCAP, SIG_PCAPNG,
    # System / Misc
    SIG_LNK, SIG_REG, SIG_GPG, SIG_PLIST, SIG_DER,
]


def get_all_categories() -> list[str]:
    """Return sorted unique categories."""
    return sorted(set(s.category for s in ALL_SIGNATURES))


def get_signatures_by_category(category: str) -> list[SignatureInfo]:
    return [s for s in ALL_SIGNATURES if s.category == category]


def get_extensions_for_category(category: str) -> list[str]:
    return sorted(set(s.extension for s in ALL_SIGNATURES if s.category == category))
