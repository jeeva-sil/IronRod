"""
Universal Data Recovery — GUI Application.

Tkinter GUI for recovering deleted files (images, videos, audio,
documents, archives, executables, fonts, databases, system files)
from any storage device (SSD, HDD, USB, SD card, NVMe, optical,
disk images) across all major filesystems (exFAT, FAT12/16/32,
NTFS, ext2/3/4, HFS+, APFS, Btrfs, XFS, F2FS, UDF, ISO 9660).
"""

APP_VERSION = "1.0"

import os
import sys
import time
import logging
import platform
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional
from collections import defaultdict

# Configure logging so save/scan errors are visible in terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

from recovery.manager import RecoveryManager, ScanSession
from recovery.scanner import ScanProgress, RecoveredFile, DriveInfo
from recovery.signatures import get_all_categories, get_extensions_for_category
from recovery.trim_detect import detect_drive_health, DriveHealthInfo, _assess_recovery
from recovery.damage_detector import analyze_damage, DamageReport
from recovery.file_repair import repair_file, RepairResult, IntegrityCheck

logger = logging.getLogger(__name__)


def _assess_recovery_with_type(health: DriveHealthInfo):
    """Re-assess recovery feasibility when drive_type is known from DriveInfo."""
    _assess_recovery(health)


# ─── Theme ────────────────────────────────────────────────────

BG_DARK     = "#1e1e2e"
BG_PANEL    = "#2a2a3c"
BG_INPUT    = "#33334d"
BG_DROPDOWN = "#ffffff"
FG_DROPDOWN = "#1a1a2e"
FG_TEXT     = "#e0e0e8"
FG_DIM      = "#8888aa"
FG_ACCENT   = "#7aa2f7"
FG_SUCCESS  = "#9ece6a"
FG_WARN     = "#e0af68"
FG_ERROR    = "#f7768e"
FG_WHITE    = "#ffffff"
FG_HEALTHY  = "#73daca"
FG_DAMAGED  = "#ff9e64"
FONT        = "Helvetica"
CHK_ON      = "■"       # large filled square for checked
CHK_OFF     = "□"       # large empty square for unchecked

CAT_ICONS = {
    "Image": "🖼️", "Video": "🎬", "Audio": "🎵", "Document": "📄",
    "Archive": "📦", "Executable": "⚙️", "Font": "🔤",
    "Database": "🗄️", "System": "🔧",
}
DAMAGE_ICONS = {
    "healthy": "✅", "minor": "⚠️", "moderate": "🟡",
    "severe": "🔴", "fatal": "💀", "unknown": "❓",
}

# ─── Ad Banner Configuration ─────────────────────────────────
# Replace AD_CLIENT and AD_SLOT with your Google AdSense IDs.
# To disable ads, set AD_ENABLED = False.
AD_ENABLED = True
AD_CLIENT = "ca-pub-1526347652539106"   # Your AdSense Publisher ID
AD_SLOT_TOP = "2901362329"              # Ad unit slot ID for top banner
AD_SLOT_BOTTOM = "2901362329"           # Ad unit slot ID for bottom banner
AD_BANNER_HEIGHT = 90                    # Banner height in pixels
# Optional: serve ads from your own page (set to "" to use inline AdSense)
AD_URL_TOP = ""     # e.g. "https://yoursite.com/ads/top-banner.html"
AD_URL_BOTTOM = ""  # e.g. "https://yoursite.com/ads/bottom-banner.html"


class DataRecoveryApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.manager = RecoveryManager()
        self.drives: list[DriveInfo] = []
        self.selected_drive: Optional[DriveInfo] = None
        self.category_vars: dict[str, tk.BooleanVar] = {}
        self.recovered_files: list[RecoveredFile] = []
        self._tree_map: dict[str, RecoveredFile] = {}
        self._checked: dict[int, bool] = {}
        self._cat_ids: dict[str, str] = {}
        self._selected_group: Optional[str] = None
        # Workable tab widgets
        self._workable_tree_map: dict[str, RecoveredFile] = {}
        self._workable_checked: dict[int, bool] = {}
        self._workable_cat_ids: dict[str, str] = {}
        self._workable_selected_group: Optional[str] = None
        self._f_cat = None
        self._f_ext = None
        self._f_smin = 0
        self._f_smax = 0
        self._f_health = None  # None = All, "healthy", "damaged", "unknown"
        # Use ~/Desktop/RecoveredFiles if Desktop exists, else ~/RecoveredFiles
        _desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.isdir(_desktop):
            self._output_dir = os.path.join(_desktop, "RecoveredFiles")
        else:
            self._output_dir = os.path.join(os.path.expanduser("~"), "RecoveredFiles")
        self._drive_health: Optional[DriveHealthInfo] = None
        self._validation_paused = threading.Event()
        self._validation_paused.set()  # Start in non-paused state
        self._validation_cancelled = False

        self._setup_window()
        self._setup_styles()
        self._build_ui()
        self._refresh_drives()

    # ─── Window ───────────────────────────────────────────────

    def _setup_window(self):
        self.root.title(f"📸 IronRod Data Recovery  v{APP_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG_DARK)
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1200) // 2
        y = (self.root.winfo_screenheight() - 800) // 2
        self.root.geometry(f"+{x}+{y}")

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=BG_DARK, foreground=FG_TEXT, font=(FONT, 11))
        s.configure("TFrame", background=BG_DARK)
        s.configure("Panel.TFrame", background=BG_PANEL)
        s.configure("TLabel", background=BG_DARK, foreground=FG_TEXT, font=(FONT, 11))
        s.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT)
        s.configure("Header.TLabel", background=BG_DARK, foreground=FG_ACCENT,
                     font=(FONT, 14, "bold"))
        s.configure("PanelHeader.TLabel", background=BG_PANEL, foreground=FG_ACCENT,
                     font=(FONT, 14, "bold"))
        s.configure("Title.TLabel", background=BG_DARK, foreground=FG_WHITE,
                     font=(FONT, 20, "bold"))
        s.configure("Status.TLabel", background=BG_PANEL, foreground=FG_DIM,
                     font=(FONT, 10))
        s.configure("FilterLabel.TLabel", background=BG_PANEL, foreground=FG_TEXT,
                     font=(FONT, 10))
        s.configure("Count.TLabel", background=BG_PANEL, foreground=FG_WARN,
                     font=(FONT, 11, "bold"))

        s.configure("Accent.TButton", background=FG_ACCENT, foreground=FG_WHITE,
                     font=(FONT, 12, "bold"), padding=(20, 10))
        s.map("Accent.TButton",
               background=[("active", "#5b8ad8"), ("disabled", "#555577")])
        s.configure("Save.TButton", background=FG_SUCCESS, foreground=FG_WHITE,
                     font=(FONT, 12, "bold"), padding=(20, 10))
        s.map("Save.TButton",
               background=[("active", "#7ab55a"), ("disabled", "#555577")])
        s.configure("Danger.TButton", background=FG_ERROR, foreground=FG_WHITE,
                     font=(FONT, 11, "bold"), padding=(15, 8))
        s.map("Danger.TButton", background=[("active", "#d45060")])
        s.configure("Secondary.TButton", background=BG_INPUT, foreground=FG_TEXT,
                     font=(FONT, 11), padding=(15, 8))
        s.map("Secondary.TButton", background=[("active", "#444466")])
        s.configure("Small.TButton", background=BG_INPUT, foreground=FG_TEXT,
                     font=(FONT, 9), padding=(8, 4))
        s.map("Small.TButton", background=[("active", "#444466")])
        s.configure("SelectAll.TButton", background="#2d5a27", foreground=FG_WHITE,
                     font=(FONT, 9, "bold"), padding=(10, 5))
        s.map("SelectAll.TButton", background=[("active", "#3a7a32")])
        s.configure("SelectNone.TButton", background="#5a2727", foreground=FG_WHITE,
                     font=(FONT, 9, "bold"), padding=(10, 5))
        s.map("SelectNone.TButton", background=[("active", "#7a3232")])

        s.configure("Custom.Horizontal.TProgressbar",
                     troughcolor=BG_INPUT, background=FG_ACCENT, thickness=25)
        s.configure("Category.TCheckbutton", background=BG_PANEL,
                     foreground=FG_TEXT, font=(FONT, 12))
        s.map("Category.TCheckbutton", background=[("active", BG_PANEL)])

        # ── Combobox styles: white background, dark readable text ──
        s.configure("TCombobox",
                     fieldbackground=BG_DROPDOWN,
                     background=BG_DROPDOWN,
                     foreground=FG_DROPDOWN,
                     arrowcolor=FG_DROPDOWN,
                     selectbackground=FG_ACCENT,
                     selectforeground=FG_WHITE,
                     padding=(6, 4),
                     font=(FONT, 11))
        s.map("TCombobox",
               fieldbackground=[("readonly", BG_DROPDOWN)],
               foreground=[("readonly", FG_DROPDOWN)],
               selectbackground=[("readonly", BG_DROPDOWN)],
               selectforeground=[("readonly", FG_DROPDOWN)])
        # Dropdown list styling
        self.root.option_add("*TCombobox*Listbox.background", BG_DROPDOWN)
        self.root.option_add("*TCombobox*Listbox.foreground", FG_DROPDOWN)
        self.root.option_add("*TCombobox*Listbox.font", f"{FONT} 11")
        self.root.option_add("*TCombobox*Listbox.selectBackground", FG_ACCENT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", FG_WHITE)

        # ── Treeview: bigger rows for larger checkboxes ──
        s.configure("Treeview", background=BG_INPUT, foreground=FG_TEXT,
                     fieldbackground=BG_INPUT, rowheight=36, font=(FONT, 11))
        s.configure("Treeview.Heading", background=BG_PANEL, foreground=FG_ACCENT,
                     font=(FONT, 10, "bold"), padding=(4, 6))
        s.map("Treeview",
               background=[("selected", FG_ACCENT)],
               foreground=[("selected", FG_WHITE)])

        # ── Notebook tabs: dark background with readable text ──
        s.configure("TNotebook", background=BG_DARK, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG_INPUT, foreground="#1a1a2e",
                     font=(FONT, 12, "bold"), padding=(18, 8))
        s.map("TNotebook.Tab",
               background=[("selected", FG_ACCENT), ("active", "#444466")],
               foreground=[("selected", FG_WHITE), ("active", "#1a1a2e")])

    # ─── Build UI ─────────────────────────────────────────────

    def _build_ui(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Title bar
        tf = ttk.Frame(self.main_frame)
        tf.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(tf, text="📸 Deleted Photo & Video Recovery",
                   style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(tf, text="Raw sector scan → File carving → Save",
                   style="Status.TLabel").pack(side=tk.LEFT, padx=(15, 0), pady=(8, 0))

        content = ttk.Frame(self.main_frame)
        content.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self._build_sidebar(content)
        self._build_main(content)

        # Bottom ad banner
        if AD_ENABLED:
            self._build_ad_banner(self.main_frame, position="bottom")

    # ─── Ad Banners ───────────────────────────────────────────

    def _build_ad_banner(self, parent, position="top"):
        """Build a small AdSense ad banner embedded in the app.

        Uses tkinterweb.HtmlFrame for a real inline browser widget that
        supports JavaScript (required for AdSense).  Falls back to a
        clickable canvas placeholder when tkinterweb is unavailable.
        """
        is_sidebar = position == "sidebar"
        ad_slot = (AD_SLOT_BOTTOM if is_sidebar
                   else (AD_SLOT_TOP if position == "top" else AD_SLOT_BOTTOM))
        ad_url = (AD_URL_BOTTOM if is_sidebar
                  else (AD_URL_TOP if position == "top" else AD_URL_BOTTOM))
        ad_h = 260 if is_sidebar else AD_BANNER_HEIGHT
        pady = (5, 10) if is_sidebar else ((0, 8) if position == "top" else (8, 0))

        ad_frame = ttk.Frame(parent, style="Panel.TFrame")
        if is_sidebar:
            ad_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=pady)
        else:
            ad_frame.pack(fill=tk.X, pady=pady)

        # ── AdSense HTML snippet ──
        ad_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  html, body {{ margin:0; padding:0; background:{BG_PANEL};
    overflow:hidden; width:100%; height:{ad_h}px; }}
  .ad-container {{ display:flex; align-items:center;
    justify-content:center; width:100%; height:100%; }}
  .ad-loading {{ color:#8888aa; font-family:Helvetica,sans-serif;
    font-size:11px; text-align:center; }}
</style></head><body>
<div class="ad-container" id="ad-box">
  <div class="ad-loading">Loading ad…</div>
</div>
<script async
  src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={AD_CLIENT}"
  crossorigin="anonymous"></script>
<ins class="adsbygoogle"
  style="display:block"
  data-ad-client="{AD_CLIENT}"
  data-ad-slot="{ad_slot}"
  data-ad-format="auto"
  data-full-width-responsive="true"></ins>
<script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
</body></html>"""

        # ── Try tkinterweb for hosted ad URL (real web pages work) ──
        if ad_url:
            try:
                from tkinterweb import HtmlFrame  # type: ignore

                browser = HtmlFrame(ad_frame, height=ad_h,
                                    messages_enabled=False)
                browser.pack(fill=tk.X)
                browser.load_url(ad_url)
                logger.debug("Ad banner (%s) loaded via tkinterweb URL", position)
                return
            except Exception as exc:
                logger.debug("tkinterweb unavailable (%s) — using fallback", exc)

        # ── Clickable banner that opens the real AdSense page
        #    in the system browser (AdSense JS cannot run inside
        #    tkinterweb / tkhtml — it has no JS engine). ──
        self._build_fallback_ad(ad_frame, position, ad_slot, ad_h, ad_html)

    def _build_fallback_ad(self, parent, position, ad_slot, ad_h, ad_html=""):
        """Clickable banner that opens the real AdSense ad page in the
        user's default system browser (since AdSense JS cannot run inside
        a Tkinter widget)."""
        cx = 130 if position == "sidebar" else 600

        banner = tk.Canvas(
            parent, height=ad_h, bg="#2d2d44",
            highlightthickness=1, highlightbackground="#444466",
            cursor="hand2",
        )
        banner.pack(fill=tk.X)
        banner.create_rectangle(0, 0, 2000, ad_h, fill="#2d2d44", outline="")
        banner.create_text(20, 14, text="Ad", fill="#555577", font=(FONT, 8))

        if position == "sidebar":
            banner.create_text(cx, ad_h // 2 - 30, text="📢",
                               fill=FG_ACCENT, font=(FONT, 28))
            banner.create_text(cx, ad_h // 2 + 10, text="Support\nDevelopment",
                               fill=FG_ACCENT, font=(FONT, 11, "bold"),
                               justify=tk.CENTER)
            banner.create_text(cx, ad_h // 2 + 50,
                               text="Click to view ad\nin your browser",
                               fill=FG_DIM, font=(FONT, 9), justify=tk.CENTER)
        else:
            banner.create_text(cx, ad_h // 2 - 10,
                               text="📢  Support Development — Click Here",
                               fill=FG_ACCENT, font=(FONT, 13, "bold"))
            banner.create_text(cx, ad_h // 2 + 14,
                               text="Help us keep this tool free • Opens in your browser",
                               fill=FG_DIM, font=(FONT, 10))

        # Build the full AdSense page to open in the system browser
        _ad_page_html = ad_html if ad_html else f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Support Data Recovery Tool</title>
<style>body{{margin:0;padding:20px;background:#1e1e2e;color:#e0e0e8;
font-family:Helvetica,sans-serif;text-align:center;}}
h2{{color:#7aa2f7;}} p{{color:#8888aa;font-size:14px;}}
.ad-box{{margin:30px auto;max-width:728px;}}</style></head>
<body>
<h2>📢 Thank you for supporting Data Recovery Tool!</h2>
<p>This free tool is supported by ads.</p>
<div class="ad-box">
<script async
  src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={AD_CLIENT}"
  crossorigin="anonymous"></script>
<ins class="adsbygoogle" style="display:block"
  data-ad-client="{AD_CLIENT}" data-ad-slot="{ad_slot}"
  data-ad-format="auto" data-full-width-responsive="true"></ins>
<script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
</div></body></html>"""

        def _open_ad(event=None):
            import tempfile
            try:
                tmp = os.path.join(tempfile.gettempdir(), "datarecovery_ad.html")
                with open(tmp, "w") as f:
                    f.write(_ad_page_html)
                webbrowser.open(f"file://{tmp}")
            except Exception:
                webbrowser.open("https://google.com")

        banner.bind("<Button-1>", _open_ad)

    # ─── Sidebar ──────────────────────────────────────────────

    def _build_sidebar(self, parent):
        sb = ttk.Frame(parent, style="Panel.TFrame", width=280)
        sb.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sb.pack_propagate(False)

        inner = ttk.Frame(sb, style="Panel.TFrame")
        inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=(15, 5))

        # Drive selection
        ttk.Label(inner, text="📀 Select Drive",
                   style="PanelHeader.TLabel").pack(anchor=tk.W)
        df = ttk.Frame(inner, style="Panel.TFrame")
        df.pack(fill=tk.X, pady=(8, 0))
        self.drive_combo = ttk.Combobox(df, state="readonly", font=(FONT, 10), width=24)
        self.drive_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.drive_combo.bind("<<ComboboxSelected>>", self._on_drive_sel)
        ttk.Button(df, text="⟳", width=3, command=self._refresh_drives,
                    style="Secondary.TButton").pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(df, text="📁", width=3, command=self._open_disk_image,
                    style="Secondary.TButton").pack(side=tk.RIGHT, padx=(2, 0))

        self.drive_info = ttk.Label(inner, text="No drive selected",
                                     style="Status.TLabel", wraplength=240)
        self.drive_info.pack(anchor=tk.W, pady=(5, 0))

        # Drive health / TRIM warning
        self.health_lbl = ttk.Label(inner, text="",
                                     style="Status.TLabel", wraplength=240)
        self.health_lbl.pack(anchor=tk.W, pady=(3, 0))

        ttk.Separator(inner, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # File type filters
        ttk.Label(inner, text="📂 Recovery Targets",
                   style="PanelHeader.TLabel").pack(anchor=tk.W)
        ttk.Label(inner, text="Recovers 95+ file types from any\nstorage device & filesystem.",
                   style="Status.TLabel", wraplength=240).pack(anchor=tk.W, pady=(5, 0))

        cf = ttk.Frame(inner, style="Panel.TFrame")
        cf.pack(fill=tk.X, pady=(10, 0))
        for cat in get_all_categories():
            var = tk.BooleanVar(value=True)
            self.category_vars[cat] = var
            icon = CAT_ICONS.get(cat, "📁")
            exts = ", ".join(e.upper() for e in get_extensions_for_category(cat))
            ttk.Checkbutton(cf, text=f"  {icon}  {cat}  ({exts})",
                             variable=var, style="Category.TCheckbutton"
                             ).pack(anchor=tk.W, pady=3)

        ttk.Separator(inner, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Notes
        nf = ttk.Frame(inner, style="Panel.TFrame")
        nf.pack(fill=tk.X)
        ttk.Label(nf, text="⚠️  Raw Disk Access Required",
                   style="Panel.TLabel", font=(FONT, 10, "bold"),
                   foreground=FG_WARN).pack(anchor=tk.W)
        ttk.Label(nf, text="Run with sudo (macOS/Linux) or\nAdministrator (Windows).",
                   style="Status.TLabel", wraplength=240).pack(anchor=tk.W, pady=(3, 0))

        # Bottom
        bottom = ttk.Frame(sb, style="Panel.TFrame")
        bottom.pack(fill=tk.X, side=tk.BOTTOM, padx=15, pady=(5, 15))
        ttk.Separator(bottom, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 10))
        ttk.Label(bottom, text="🔒 Read-Only — source drive is never modified",
                   style="Status.TLabel", wraplength=240).pack(anchor=tk.W, pady=(0, 8))

        self.scan_btn = ttk.Button(bottom, text="⚡  Scan for Deleted Files",
                                    command=self._start_scan, style="Accent.TButton")
        self.scan_btn.pack(fill=tk.X, ipady=5)

        self.cancel_btn = ttk.Button(bottom, text="⏹  Cancel Scan",
                                      command=self._cancel_scan, style="Danger.TButton")

        self.pause_btn = ttk.Button(bottom, text="⏸  Pause Verification",
                                     command=self._toggle_pause_validation,
                                     style="Secondary.TButton")

        # Sidebar ad banner
        if AD_ENABLED:
            self._build_ad_banner(sb, position="sidebar")

    # ─── Main area ────────────────────────────────────────────

    def _build_main(self, parent):
        main = ttk.Frame(parent)
        main.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Progress
        pf = ttk.Frame(main, style="Panel.TFrame")
        pf.pack(fill=tk.X, pady=(0, 10))
        pi = ttk.Frame(pf, style="Panel.TFrame")
        pi.pack(fill=tk.X, padx=15, pady=12)

        self.status_lbl = ttk.Label(pi, text="Ready — Select a drive and click Scan",
                                     style="Panel.TLabel", font=(FONT, 12))
        self.status_lbl.pack(anchor=tk.W)

        # Scan mode label (forensic vs brute-force)
        self.mode_lbl = ttk.Label(pi, text="", style="Status.TLabel")
        self.mode_lbl.pack(anchor=tk.W, pady=(2, 0))

        self.pbar = ttk.Progressbar(pi, orient=tk.HORIZONTAL, mode="determinate",
                                     style="Custom.Horizontal.TProgressbar")
        self.pbar.pack(fill=tk.X, pady=(10, 5))

        sf = ttk.Frame(pi, style="Panel.TFrame")
        sf.pack(fill=tk.X)
        self.s_pct = ttk.Label(sf, text="0%", style="Panel.TLabel")
        self.s_pct.pack(side=tk.LEFT)
        self.s_speed = ttk.Label(sf, text="", style="Status.TLabel")
        self.s_speed.pack(side=tk.LEFT, padx=(20, 0))
        self.s_eta = ttk.Label(sf, text="", style="Status.TLabel")
        self.s_eta.pack(side=tk.LEFT, padx=(20, 0))
        self.s_found = ttk.Label(sf, text="Found: 0", style="Panel.TLabel")
        self.s_found.pack(side=tk.RIGHT)

        # Toolbar
        tb = ttk.Frame(main, style="Panel.TFrame")
        tb.pack(fill=tk.X, pady=(0, 8))
        ti = ttk.Frame(tb, style="Panel.TFrame")
        ti.pack(fill=tk.X, padx=15, pady=8)

        tl = ttk.Frame(ti, style="Panel.TFrame")
        tl.pack(side=tk.LEFT)
        ttk.Label(tl, text="📋 Recovered Deleted Files",
                   style="PanelHeader.TLabel").pack(side=tk.LEFT)
        self.sel_lbl = ttk.Label(tl, text="", style="Count.TLabel")
        self.sel_lbl.pack(side=tk.LEFT, padx=(15, 0))

        tr = ttk.Frame(ti, style="Panel.TFrame")
        tr.pack(side=tk.RIGHT)
        self.save_btn = ttk.Button(tr, text="💾  Save Selected",
                                    command=self._save_selected, style="Save.TButton")
        self.save_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(tr, text="🩺 Analyze", command=self._analyze_damage,
                    style="Small.TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tr, text="🔧 Repair", command=self._repair_selected,
                    style="Small.TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tr, text="📊 CSV", command=self._export_csv,
                    style="Small.TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tr, text="📄 JSON", command=self._export_json,
                    style="Small.TButton").pack(side=tk.LEFT)

        # Save location
        sr = ttk.Frame(tb, style="Panel.TFrame")
        sr.pack(fill=tk.X, padx=15, pady=(4, 6))
        ttk.Label(sr, text="💾 Save To:", style="FilterLabel.TLabel").pack(side=tk.LEFT)
        self.out_lbl = ttk.Label(sr, text=self._short(self._output_dir, 50),
                                  style="Panel.TLabel", font=(FONT, 10))
        self.out_lbl.pack(side=tk.LEFT, padx=(8, 8))
        ttk.Button(sr, text="📂 Browse...", command=self._browse_output,
                    style="Small.TButton").pack(side=tk.LEFT)

        # Filters
        fr = ttk.Frame(tb, style="Panel.TFrame")
        fr.pack(fill=tk.X, padx=15, pady=(0, 4))
        ttk.Label(fr, text="🔎 Filter:", style="FilterLabel.TLabel",
                   font=(FONT, 11, "bold")).pack(side=tk.LEFT)

        ttk.Label(fr, text="Type:", style="FilterLabel.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.fc_combo = ttk.Combobox(fr, state="readonly", width=12, font=(FONT, 11))
        self.fc_combo["values"] = ["All Types", "Image", "Video"]
        self.fc_combo.current(0)
        self.fc_combo.pack(side=tk.LEFT)
        self.fc_combo.bind("<<ComboboxSelected>>", self._apply_filters)

        ttk.Label(fr, text="Ext:", style="FilterLabel.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.fe_combo = ttk.Combobox(fr, state="readonly", width=10, font=(FONT, 11))
        self.fe_combo["values"] = ["All"]
        self.fe_combo.current(0)
        self.fe_combo.pack(side=tk.LEFT)
        self.fe_combo.bind("<<ComboboxSelected>>", self._apply_filters)

        ttk.Label(fr, text="Size:", style="FilterLabel.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.fs_combo = ttk.Combobox(fr, state="readonly", width=16, font=(FONT, 11))
        self.fs_combo["values"] = [
            "All Sizes", "< 100 KB", "100 KB – 1 MB",
            "1 MB – 10 MB", "10 MB – 100 MB", "> 100 MB",
        ]
        self.fs_combo.current(0)
        self.fs_combo.pack(side=tk.LEFT)
        self.fs_combo.bind("<<ComboboxSelected>>", self._apply_filters)

        ttk.Label(fr, text="Health:", style="FilterLabel.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.fh_combo = ttk.Combobox(fr, state="readonly", width=16, font=(FONT, 11))
        self.fh_combo["values"] = [
            "All Files", "✅ Workable", "❌ Non-Workable",
            "❓ Unverified",
        ]
        self.fh_combo.current(0)
        self.fh_combo.pack(side=tk.LEFT)
        self.fh_combo.bind("<<ComboboxSelected>>", self._apply_filters)

        # Per-section selection buttons
        sel_spacer = ttk.Frame(fr, style="Panel.TFrame", width=10)
        sel_spacer.pack(side=tk.RIGHT)
        ttk.Button(fr, text="✅ Select Section", width=14, command=self._sel_section_all,
                    style="SelectAll.TButton").pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(fr, text="☐ Unselect Section", width=14, command=self._sel_section_none,
                    style="SelectNone.TButton").pack(side=tk.RIGHT, padx=(5, 0))

        # Results with tabs for "All Files" and "Truly Workable"
        rf = ttk.Frame(main)
        rf.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabbed interface)
        self.results_notebook = ttk.Notebook(rf)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # ─── Tab 1: All Files ───
        all_files_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(all_files_tab, text="📋 All Recovered Files")
        
        paned = ttk.PanedWindow(all_files_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Category tree (All Files)
        cp = ttk.Frame(paned, style="Panel.TFrame")
        ci = ttk.Frame(cp, style="Panel.TFrame")
        ci.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        ttk.Label(ci, text="🗂️ Categories", style="PanelHeader.TLabel").pack(anchor=tk.W)
        ttk.Separator(ci, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 6))
        ctf = ttk.Frame(ci, style="Panel.TFrame")
        ctf.pack(fill=tk.BOTH, expand=True)
        self.cat_tree = ttk.Treeview(ctf, show="tree", selectmode="browse")
        csv_ = ttk.Scrollbar(ctf, orient=tk.VERTICAL, command=self.cat_tree.yview)
        self.cat_tree.configure(yscrollcommand=csv_.set)
        self.cat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        csv_.pack(side=tk.RIGHT, fill=tk.Y)
        self.cat_tree.bind("<<TreeviewSelect>>", self._on_cat_sel)
        # Per-section Select All / Unselect All buttons under category tree
        cat_btn_frame = ttk.Frame(ci, style="Panel.TFrame")
        cat_btn_frame.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(cat_btn_frame, text="✅ Select All", width=11,
                    command=self._sel_all,
                    style="SelectAll.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(cat_btn_frame, text="☐ Unselect All", width=12,
                    command=self._sel_none,
                    style="SelectNone.TButton").pack(side=tk.LEFT)
        self.cat_sum = ttk.Label(ci, text="", style="Status.TLabel")
        self.cat_sum.pack(anchor=tk.W, pady=(4, 0))
        paned.add(cp, weight=1)

        # File list (All Files)
        fp = ttk.Frame(paned)
        fi = ttk.Frame(fp)
        fi.pack(fill=tk.BOTH, expand=True)
        cols = ("check", "name", "extension", "size", "sector", "type", "health", "source", "md5")
        self.tree = ttk.Treeview(fi, columns=cols, show="headings", selectmode="extended")
        for col, (heading, w, anch) in {
            "check": ("  ✔", 50, tk.CENTER), "name": ("File Name", 190, tk.W),
            "extension": ("Ext", 58, tk.W), "size": ("Size", 85, tk.W),
            "sector": ("Sector", 85, tk.W), "type": ("Type", 120, tk.W),
            "health": ("🩺 Health", 110, tk.W), "source": ("Source", 65, tk.W),
            "md5": ("MD5", 100, tk.W),
        }.items():
            self.tree.heading(col, text=heading, anchor=anch)
            self.tree.column(col, width=w, minwidth=35, anchor=anch)
        fvs = ttk.Scrollbar(fi, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=fvs.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fvs.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_click)
        paned.add(fp, weight=3)

        self.summary_lbl = ttk.Label(
            all_files_tab, text="No scan results. Click 'Scan for Deleted Files' to begin.",
            style="Status.TLabel")
        self.summary_lbl.pack(anchor=tk.W, pady=(5, 0))
        
        # ─── Tab 2: Truly Workable Files ───
        workable_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(workable_tab, text="✅ Truly Workable")
        
        workable_paned = ttk.PanedWindow(workable_tab, orient=tk.HORIZONTAL)
        workable_paned.pack(fill=tk.BOTH, expand=True)

        # Category tree (Workable Files)
        wcp = ttk.Frame(workable_paned, style="Panel.TFrame")
        wci = ttk.Frame(wcp, style="Panel.TFrame")
        wci.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        ttk.Label(wci, text="✅ Workable Categories", style="PanelHeader.TLabel").pack(anchor=tk.W)
        ttk.Separator(wci, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 6))
        wctf = ttk.Frame(wci, style="Panel.TFrame")
        wctf.pack(fill=tk.BOTH, expand=True)
        self.workable_cat_tree = ttk.Treeview(wctf, show="tree", selectmode="browse")
        wcsv_ = ttk.Scrollbar(wctf, orient=tk.VERTICAL, command=self.workable_cat_tree.yview)
        self.workable_cat_tree.configure(yscrollcommand=wcsv_.set)
        self.workable_cat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        wcsv_.pack(side=tk.RIGHT, fill=tk.Y)
        self.workable_cat_tree.bind("<<TreeviewSelect>>", self._on_workable_cat_sel)
        # Per-section Select All / Unselect All buttons under category tree
        wcat_btn_frame = ttk.Frame(wci, style="Panel.TFrame")
        wcat_btn_frame.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(wcat_btn_frame, text="✅ Select All", width=11,
                    command=self._sel_all_workable,
                    style="SelectAll.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(wcat_btn_frame, text="☐ Unselect All", width=12,
                    command=self._sel_none_workable,
                    style="SelectNone.TButton").pack(side=tk.LEFT)
        self.workable_cat_sum = ttk.Label(wci, text="", style="Status.TLabel")
        self.workable_cat_sum.pack(anchor=tk.W, pady=(4, 0))
        workable_paned.add(wcp, weight=1)

        # File list (Workable Files)
        wfp = ttk.Frame(workable_paned)
        wfi = ttk.Frame(wfp)
        wfi.pack(fill=tk.BOTH, expand=True)
        self.workable_tree = ttk.Treeview(wfi, columns=cols, show="headings", selectmode="extended")
        for col, (heading, w, anch) in {
            "check": ("  ✔", 50, tk.CENTER), "name": ("File Name", 190, tk.W),
            "extension": ("Ext", 58, tk.W), "size": ("Size", 85, tk.W),
            "sector": ("Sector", 85, tk.W), "type": ("Type", 120, tk.W),
            "health": ("🩺 Health", 110, tk.W), "source": ("Source", 65, tk.W),
            "md5": ("MD5", 100, tk.W),
        }.items():
            self.workable_tree.heading(col, text=heading, anchor=anch)
            self.workable_tree.column(col, width=w, minwidth=35, anchor=anch)
        wfvs = ttk.Scrollbar(wfi, orient=tk.VERTICAL, command=self.workable_tree.yview)
        self.workable_tree.configure(yscrollcommand=wfvs.set)
        self.workable_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        wfvs.pack(side=tk.RIGHT, fill=tk.Y)
        self.workable_tree.bind("<ButtonRelease-1>", self._on_workable_tree_click)
        workable_paned.add(wfp, weight=3)

        self.workable_summary_lbl = ttk.Label(
            workable_tab, text="No truly workable files yet. Run auto-validation after scanning.",
            style="Status.TLabel")
        self.workable_summary_lbl.pack(anchor=tk.W, pady=(5, 0))

        # Make "Truly Workable" the first tab
        self.results_notebook.insert(0, workable_tab)
        self.results_notebook.select(workable_tab)

    # ─── Category tree ────────────────────────────────────────

    @staticmethod
    def _workability_of(rf) -> str:
        """Return 'workable', 'non-workable', or 'unverified' for a RecoveredFile."""
        if getattr(rf, 'is_validated', False):
            if getattr(rf, 'is_truly_workable', False):
                return 'workable'
            else:
                return 'non-workable'
        return 'unverified'

    @staticmethod
    def _health_of(rf) -> str:
        """Return 'healthy', 'damaged', or 'unknown' for a RecoveredFile."""
        dmg = getattr(rf, 'damage_report', None)
        if dmg and hasattr(dmg, 'damage_level'):
            level = dmg.damage_level
            if level in ('minor', 'moderate', 'severe', 'fatal'):
                return 'damaged'
            elif level == 'healthy':
                return 'healthy'
        if not rf.is_valid:
            return 'damaged'
        return 'unknown'

    def _pop_cat_tree(self):
        self.cat_tree.delete(*self.cat_tree.get_children())
        self._cat_ids.clear()
        if not self.recovered_files:
            self.cat_sum.configure(text="")
            return

        total = len(self.recovered_files)
        # Count workability status across all files
        w_counts = {'workable': 0, 'non-workable': 0, 'unverified': 0}
        h_counts = {'healthy': 0, 'damaged': 0, 'unknown': 0}
        for rf in self.recovered_files:
            w_counts[self._workability_of(rf)] += 1
            h_counts[self._health_of(rf)] += 1

        # ── "All Files" root node ──
        all_id = self.cat_tree.insert("", tk.END,
                                       text=f"  🗂️  All Files  ({total})", open=True)
        self._cat_ids[all_id] = "__all__"

        # ── "✅ Truly Workable Files" group ──
        workable_files = [f for f in self.recovered_files
                          if self._workability_of(f) == 'workable']
        if workable_files:
            w_id = self.cat_tree.insert(all_id, tk.END,
                                         text=f"  ✅  Truly Workable  ({len(workable_files)})",
                                         open=True)
            self._cat_ids[w_id] = "__work__workable"
            w_cats: dict[str, list] = defaultdict(list)
            for rf in workable_files:
                w_cats[rf.category].append(rf)
            for cat in sorted(w_cats):
                icon = CAT_ICONS.get(cat, "📁")
                cid = self.cat_tree.insert(w_id, tk.END,
                    text=f"    {icon}  {cat}  ({len(w_cats[cat])})", open=False)
                self._cat_ids[cid] = f"__work_cat__workable__{cat}"
                exts: dict[str, int] = defaultdict(int)
                for rf in w_cats[cat]:
                    exts[rf.extension] += 1
                for ext in sorted(exts):
                    eid = self.cat_tree.insert(cid, tk.END,
                        text=f"      .{ext}  ({exts[ext]})")
                    self._cat_ids[eid] = f"__work_ext__workable__{cat}__{ext}"

        # ── "❌ Non-Workable Files" group ──
        nonwork_files = [f for f in self.recovered_files
                         if self._workability_of(f) == 'non-workable']
        if nonwork_files:
            n_id = self.cat_tree.insert(all_id, tk.END,
                                         text=f"  ❌  Non-Workable  ({len(nonwork_files)})",
                                         open=False)
            self._cat_ids[n_id] = "__work__non-workable"
            n_cats: dict[str, list] = defaultdict(list)
            for rf in nonwork_files:
                n_cats[rf.category].append(rf)
            for cat in sorted(n_cats):
                icon = CAT_ICONS.get(cat, "📁")
                reason_counts: dict[str, int] = defaultdict(int)
                for rf in n_cats[cat]:
                    reason_counts[getattr(rf, 'workability_reason', 'Unknown')] += 1
                top_reason = max(reason_counts, key=reason_counts.get) if reason_counts else ""
                short_reason = top_reason[:30] + "…" if len(top_reason) > 30 else top_reason
                cid = self.cat_tree.insert(n_id, tk.END,
                    text=f"    {icon}  {cat}  ({len(n_cats[cat])})", open=False)
                self._cat_ids[cid] = f"__work_cat__non-workable__{cat}"
                exts: dict[str, int] = defaultdict(int)
                for rf in n_cats[cat]:
                    exts[rf.extension] += 1
                for ext in sorted(exts):
                    eid = self.cat_tree.insert(cid, tk.END,
                        text=f"      .{ext}  ({exts[ext]})")
                    self._cat_ids[eid] = f"__work_ext__non-workable__{cat}__{ext}"

        # ── "❓ Unverified" group (not yet deep-validated) ──
        unverified_files = [f for f in self.recovered_files
                            if self._workability_of(f) == 'unverified']
        if unverified_files:
            u_id = self.cat_tree.insert(all_id, tk.END,
                                         text=f"  ❓  Unverified  ({len(unverified_files)})",
                                         open=True)
            self._cat_ids[u_id] = "__work__unverified"
            u_cats: dict[str, list] = defaultdict(list)
            for rf in unverified_files:
                u_cats[rf.category].append(rf)
            for cat in sorted(u_cats):
                icon = CAT_ICONS.get(cat, "📁")
                cid = self.cat_tree.insert(u_id, tk.END,
                    text=f"    {icon}  {cat}  ({len(u_cats[cat])})", open=False)
                self._cat_ids[cid] = f"__work_cat__unverified__{cat}"
                exts: dict[str, int] = defaultdict(int)
                for rf in u_cats[cat]:
                    exts[rf.extension] += 1
                for ext in sorted(exts):
                    eid = self.cat_tree.insert(cid, tk.END,
                        text=f"      .{ext}  ({exts[ext]})")
                    self._cat_ids[eid] = f"__work_ext__unverified__{cat}__{ext}"

        # ── By Type (flat) ──
        cats_all: dict[str, list] = defaultdict(list)
        for rf in self.recovered_files:
            cats_all[rf.category].append(rf)
        for cat in sorted(cats_all):
            files = cats_all[cat]
            icon = CAT_ICONS.get(cat, "📁")
            cat_w = sum(1 for f in files if self._workability_of(f) == 'workable')
            cat_nw = sum(1 for f in files if self._workability_of(f) == 'non-workable')
            tag = ""
            if cat_w > 0:
                tag += f"  ✅{cat_w}"
            if cat_nw > 0:
                tag += f"  ❌{cat_nw}"
            cid = self.cat_tree.insert(all_id, tk.END,
                                        text=f"  {icon}  {cat}  ({len(files)}){tag}",
                                        open=False)
            self._cat_ids[cid] = f"__cat__{cat}"
            exts: dict[str, int] = defaultdict(int)
            for rf in files:
                exts[rf.extension] += 1
            for ext in sorted(exts):
                eid = self.cat_tree.insert(cid, tk.END,
                    text=f"      .{ext}  ({exts[ext]})")
                self._cat_ids[eid] = f"__ext__{cat}__{ext}"

        # Summary with workability breakdown
        parts = [f"{total} file(s) found"]
        if w_counts['workable'] > 0:
            parts.append(f"✅ {w_counts['workable']} workable")
        if w_counts['non-workable'] > 0:
            parts.append(f"❌ {w_counts['non-workable']} non-workable")
        if w_counts['unverified'] > 0:
            parts.append(f"❓ {w_counts['unverified']} unverified")
        self.cat_sum.configure(text="  •  ".join(parts))

    def _on_cat_sel(self, event=None):
        sel = self.cat_tree.selection()
        if not sel:
            return
        key = self._cat_ids.get(sel[0])
        if not key:
            return
        self._selected_group = key
        if key == "__all__":
            files = self.recovered_files
        elif key.startswith("__work__"):
            # Top-level workability group: workable / non-workable / unverified
            work = key[len("__work__"):]
            files = [f for f in self.recovered_files
                     if self._workability_of(f) == work]
        elif key.startswith("__work_cat__"):
            # Workability + category
            rest = key[len("__work_cat__"):]
            work, cat = rest.split("__", 1)
            files = [f for f in self.recovered_files
                     if self._workability_of(f) == work and f.category == cat]
        elif key.startswith("__work_ext__"):
            # Workability + category + extension
            rest = key[len("__work_ext__"):]
            parts = rest.split("__", 2)
            work, cat, ext = parts[0], parts[1], parts[2]
            files = [f for f in self.recovered_files
                     if self._workability_of(f) == work
                     and f.category == cat and f.extension == ext]
        elif key.startswith("__health__"):
            # Top-level health group: healthy / damaged / unknown
            health = key[len("__health__"):]
            files = [f for f in self.recovered_files
                     if self._health_of(f) == health]
        elif key.startswith("__health_cat__"):
            # Health + category: e.g. __health_cat__healthy__Image
            rest = key[len("__health_cat__"):]
            health, cat = rest.split("__", 1)
            files = [f for f in self.recovered_files
                     if self._health_of(f) == health and f.category == cat]
        elif key.startswith("__health_ext__"):
            # Health + category + extension: e.g. __health_ext__healthy__Image__jpg
            rest = key[len("__health_ext__"):]
            parts = rest.split("__", 2)
            health, cat, ext = parts[0], parts[1], parts[2]
            files = [f for f in self.recovered_files
                     if self._health_of(f) == health
                     and f.category == cat and f.extension == ext]
        elif key.startswith("__cat__"):
            cat = key[7:]
            files = [f for f in self.recovered_files if f.category == cat]
        elif key.startswith("__ext__"):
            parts = key[7:].split("__", 1)
            files = [f for f in self.recovered_files
                     if f.category == parts[0] and f.extension == parts[1]]
        else:
            files = self.recovered_files
        self._pop_file_list(self._apply_filter(files))

    # ─── File list ────────────────────────────────────────────

    def _pop_file_list(self, files):
        self.tree.delete(*self.tree.get_children())
        self._tree_map.clear()
        for rf in files:
            k = id(rf)
            if k not in self._checked:
                self._checked[k] = True
            chk = CHK_ON if self._checked[k] else CHK_OFF
            md5s = rf.md5[:12] + "…" if rf.md5 else "—"
            src_tag = "🔍 TSK" if getattr(rf, 'source', 'carved') == 'tsk' else "⛏ Carve"
            # Workability / Health status
            work_status = self._workability_of(rf)
            if work_status == 'workable':
                health = "✅ Workable"
                row_tag = "workable"
            elif work_status == 'non-workable':
                reason = getattr(rf, 'workability_reason', '')
                short = reason[:25] + "…" if len(reason) > 25 else reason
                health = f"❌ {short}" if short else "❌ Non-Workable"
                row_tag = "nonworkable"
            else:
                # Fall back to damage report
                dmg = getattr(rf, 'damage_report', None)
                if dmg and hasattr(dmg, 'damage_level'):
                    icon = DAMAGE_ICONS.get(dmg.damage_level, "❓")
                    if getattr(rf, 'is_repaired', False):
                        health = f"{icon} Repaired"
                    else:
                        health = f"{icon} {dmg.damage_level.capitalize()}"
                else:
                    if not rf.is_valid:
                        health = "⚠️ Corrupted"
                    else:
                        health = "❓ Unverified"
                file_health = self._health_of(rf)
                if file_health == 'damaged':
                    row_tag = "damaged"
                elif file_health == 'healthy':
                    row_tag = "healthy"
                else:
                    row_tag = "file"
            iid = self.tree.insert("", tk.END, values=(
                chk, rf.display_name, f".{rf.extension}",
                rf.size_human, f"#{rf.sector:,}", rf.description,
                health, src_tag, md5s,
            ), tags=(row_tag,))
            self._tree_map[iid] = rf
        # Apply tag-based colors for clear visual distinction
        self.tree.tag_configure("workable", foreground=FG_SUCCESS)
        self.tree.tag_configure("nonworkable", foreground=FG_ERROR)
        self.tree.tag_configure("damaged", foreground=FG_DAMAGED)
        self.tree.tag_configure("healthy", foreground=FG_HEALTHY)
        self.tree.tag_configure("file", foreground=FG_TEXT)
        self._update_sel()

    def _pop_tree(self, files=None):
        self._pop_cat_tree()
        self._pop_workable_cat_tree()  # Also populate the workable tab
        self._update_ext_combo(files or self.recovered_files)
        self._update_sel()
        if self._selected_group:
            self._on_cat_sel()
        elif self.recovered_files:
            # Always base default selection on all recovered files, not filtered files
            all_workable = [f for f in self.recovered_files if self._workability_of(f) == 'workable']
            if all_workable:
                self._selected_group = "__work__workable"
                for iid, key in self._cat_ids.items():
                    if key == "__work__workable":
                        self.cat_tree.selection_set(iid)
                        self.cat_tree.see(iid)
                        break
                # Show only workable files, but apply current filters
                self._pop_file_list(self._apply_filter([f for f in (files or self.recovered_files) if self._workability_of(f) == 'workable']))
            else:
                self._selected_group = "__all__"
                for iid, key in self._cat_ids.items():
                    if key == "__all__":
                        self.cat_tree.selection_set(iid)
                        self.cat_tree.see(iid)
                        break
                self._pop_file_list(self._apply_filter(files or self.recovered_files))

    def _apply_filter(self, files):
        out = []
        for rf in files:
            if self._f_cat and rf.category != self._f_cat:
                continue
            if self._f_ext and rf.extension != self._f_ext:
                continue
            if self._f_smin and rf.size < self._f_smin:
                continue
            if self._f_smax and rf.size > self._f_smax:
                continue
            if self._f_health:
                w = self._workability_of(rf)
                if w != self._f_health:
                    continue
            out.append(rf)
        return out

    def _update_ext_combo(self, files):
        exts = sorted(set(f.extension for f in files))
        self.fe_combo["values"] = ["All"] + [f".{e}" for e in exts]
        if self._f_ext is None:
            self.fe_combo.current(0)

    def _update_sel(self):
        total = len(self.recovered_files)
        # Count unique selections from both tabs
        # _checked defaults True (all files selected initially)
        # _workable_checked defaults False (only explicitly checked in workable tab)
        selected_ids = set()
        for f in self.recovered_files:
            fid = id(f)
            if self._checked.get(fid, True) or self._workable_checked.get(fid, False):
                selected_ids.add(fid)
        sel = len(selected_ids)
        sz = sum(f.size for f in self.recovered_files 
                 if id(f) in selected_ids)
        self.sel_lbl.configure(text=f"{sel}/{total} selected ({_fmt(sz)})" if total else "")

    # ─── Tree click ───────────────────────────────────────────

    def _on_tree_click(self, event):
        col = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        if not item or col != "#1":
            return
        tags = self.tree.item(item, "tags")
        valid_tags = ("file", "damaged", "healthy", "workable", "nonworkable")
        if tags and tags[0] in valid_tags:
            rf = self._tree_map.get(item)
            if rf is None:
                return
            k = id(rf)
            new = not self._checked.get(k, True)
            self._checked[k] = new
            vals = list(self.tree.item(item, "values"))
            vals[0] = CHK_ON if new else CHK_OFF
            self.tree.item(item, values=vals)
            self._update_sel()

    def _sel_all(self):
        """Select all currently visible files (respects active filters)."""
        visible = self._get_visible_files()
        for f in visible:
            self._checked[id(f)] = True
        # Update the treeview checkboxes in-place for instant feedback
        for iid in self.tree.get_children():
            rf = self._tree_map.get(iid)
            if rf and self._checked.get(id(rf), True):
                vals = list(self.tree.item(iid, "values"))
                vals[0] = CHK_ON
                self.tree.item(iid, values=vals)
        self._update_sel()

    def _sel_none(self):
        """Deselect all currently visible files (respects active filters)."""
        visible = self._get_visible_files()
        for f in visible:
            self._checked[id(f)] = False
        # Update the treeview checkboxes in-place for instant feedback
        for iid in self.tree.get_children():
            rf = self._tree_map.get(iid)
            if rf:
                vals = list(self.tree.item(iid, "values"))
                vals[0] = CHK_OFF
                self.tree.item(iid, values=vals)
        self._update_sel()

    def _sel_section_all(self):
        """Select all files in the currently visible section."""
        visible = self._get_visible_files()
        for f in visible:
            self._checked[id(f)] = True
        for iid in self.tree.get_children():
            rf = self._tree_map.get(iid)
            if rf and self._checked.get(id(rf), True):
                vals = list(self.tree.item(iid, "values"))
                vals[0] = CHK_ON
                self.tree.item(iid, values=vals)
        self._update_sel()

    def _sel_section_none(self):
        """Unselect all files in the currently visible section."""
        visible = self._get_visible_files()
        for f in visible:
            self._checked[id(f)] = False
        for iid in self.tree.get_children():
            rf = self._tree_map.get(iid)
            if rf:
                vals = list(self.tree.item(iid, "values"))
                vals[0] = CHK_OFF
                self.tree.item(iid, values=vals)
        self._update_sel()

    def _get_visible_files(self):
        """Return the list of RecoveredFiles currently displayed in the tree."""
        return [rf for iid in self.tree.get_children()
                for rf in [self._tree_map.get(iid)] if rf is not None]

    # ─── Workable Tab Handlers ────────────────────────────────

    def _pop_workable_cat_tree(self):
        """Populate the category tree for the Truly Workable tab."""
        self.workable_cat_tree.delete(*self.workable_cat_tree.get_children())
        self._workable_cat_ids.clear()
        
        workable_files = [f for f in self.recovered_files
                          if self._workability_of(f) == 'workable']
        
        if not workable_files:
            self.workable_cat_sum.configure(text="No truly workable files yet")
            return
        
        total = len(workable_files)
        all_id = self.workable_cat_tree.insert("", tk.END,
                                                text=f"  ✅  All Workable Files  ({total})", open=True)
        self._workable_cat_ids[all_id] = "__all_workable__"
        
        # By Category
        cats: dict[str, list] = defaultdict(list)
        for rf in workable_files:
            cats[rf.category].append(rf)
        
        for cat in sorted(cats):
            files = cats[cat]
            icon = CAT_ICONS.get(cat, "📁")
            cid = self.workable_cat_tree.insert(all_id, tk.END,
                                                 text=f"  {icon}  {cat}  ({len(files)})",
                                                 open=False)
            self._workable_cat_ids[cid] = f"__wcat__{cat}"
            
            # By Extension
            exts: dict[str, int] = defaultdict(int)
            for rf in files:
                exts[rf.extension] += 1
            for ext in sorted(exts):
                eid = self.workable_cat_tree.insert(cid, tk.END,
                                                     text=f"      .{ext}  ({exts[ext]})")
                self._workable_cat_ids[eid] = f"__wext__{cat}__{ext}"
        
        self.workable_cat_sum.configure(text=f"{total} truly workable file(s)")

    def _on_workable_cat_sel(self, event=None):
        """Handle category selection in the workable tab."""
        sel = self.workable_cat_tree.selection()
        if not sel:
            return
        key = self._workable_cat_ids.get(sel[0])
        if not key:
            return
        self._workable_selected_group = key
        
        workable_files = [f for f in self.recovered_files
                          if self._workability_of(f) == 'workable']
        
        if key == "__all_workable__":
            files = workable_files
        elif key.startswith("__wcat__"):
            cat = key[len("__wcat__"):]
            files = [f for f in workable_files if f.category == cat]
        elif key.startswith("__wext__"):
            rest = key[len("__wext__"):]
            cat, ext = rest.split("__", 1)
            files = [f for f in workable_files
                     if f.category == cat and f.extension == ext]
        else:
            files = workable_files
        
        self._pop_workable_tree(files)

    def _pop_workable_tree(self, files):
        """Populate the file list for the workable tab."""
        self.workable_tree.delete(*self.workable_tree.get_children())
        self._workable_tree_map.clear()
        
        if not files:
            self.workable_summary_lbl.configure(text="No files in this category.")
            return
        
        for rf in files:
            dmg = getattr(rf, 'damage_report', None)
            health = "✅ Healthy"
            if dmg and hasattr(dmg, 'damage_level'):
                level = dmg.damage_level
                if level == 'minor':
                    health = "⚠️ Minor"
                elif level == 'moderate':
                    health = "⚠️ Moderate"
                elif level in ('severe', 'fatal'):
                    health = "❌ Severe"
            
            k = id(rf)
            chk = self._workable_checked.get(k, True)
            vals = (
                CHK_ON if chk else CHK_OFF,
                rf.display_name,
                f".{rf.extension}",
                _fmt(rf.size),
                str(rf.sector) if rf.sector >= 0 else "",
                rf.category,
                health,
                rf.source or "TSK",
                (rf.md5 or "")[:12] + ("…" if rf.md5 and len(rf.md5) > 12 else ""),
            )
            iid = self.workable_tree.insert("", tk.END, values=vals, tags=("workable",))
            self._workable_tree_map[iid] = rf
        
        self.workable_summary_lbl.configure(text=f"{len(files)} truly workable file(s)")

    def _on_workable_tree_click(self, event):
        """Handle checkbox clicks in the workable tab tree."""
        col = self.workable_tree.identify_column(event.x)
        item = self.workable_tree.identify_row(event.y)
        if not item or col != "#1":
            return
        
        rf = self._workable_tree_map.get(item)
        if rf is None:
            return
        
        k = id(rf)
        new = not self._workable_checked.get(k, True)
        self._workable_checked[k] = new
        vals = list(self.workable_tree.item(item, "values"))
        vals[0] = CHK_ON if new else CHK_OFF
        self.workable_tree.item(item, values=vals)

    def _sel_all_workable(self):
        """Select all files in the workable tab."""
        for iid in self.workable_tree.get_children():
            rf = self._workable_tree_map.get(iid)
            if rf:
                self._workable_checked[id(rf)] = True
                vals = list(self.workable_tree.item(iid, "values"))
                vals[0] = CHK_ON
                self.workable_tree.item(iid, values=vals)

    def _sel_none_workable(self):
        """Unselect all files in the workable tab."""
        for iid in self.workable_tree.get_children():
            rf = self._workable_tree_map.get(iid)
            if rf:
                self._workable_checked[id(rf)] = False
                vals = list(self.workable_tree.item(iid, "values"))
                vals[0] = CHK_OFF
                self.workable_tree.item(iid, values=vals)

    # ─── Damage Analysis & Repair ─────────────────────────────

    def _analyze_damage(self):
        """Analyze selected files for damage in a background thread."""
        # Combine selections from both tabs
        files = [f for f in self.recovered_files
                 if self._checked.get(id(f), True) or self._workable_checked.get(id(f), False)]
        
        if not files:
            messagebox.showinfo("Nothing", "No files selected.")
            return

        # Check raw device access
        valid = [f for f in files if f.raw_device_path and f.size > 0]
        if not valid:
            messagebox.showerror("Error", "Selected files have no raw device path.")
            return

        self.status_lbl.configure(text=f"🩺 Analyzing {len(valid)} files for damage...")
        self.scan_btn.configure(state="disabled")

        def do_analyze():
            for i, rf in enumerate(valid):
                try:
                    self.manager.analyze_file_damage(rf)
                except Exception as e:
                    logger.warning("Damage analysis failed for %s: %s",
                                   rf.display_name, e)
                if (i + 1) % 5 == 0 or i == len(valid) - 1:
                    self.root.after(0, lambda c=i+1: self.status_lbl.configure(
                        text=f"🩺 Analyzed {c}/{len(valid)} files..."))
            self.root.after(0, self._analysis_done, valid)

        threading.Thread(target=do_analyze, daemon=True).start()

    def _analysis_done(self, files):
        """Called when damage analysis completes."""
        self.scan_btn.configure(state="normal")
        self._pop_tree()

        # Count damage levels
        counts = {"healthy": 0, "minor": 0, "moderate": 0,
                  "severe": 0, "fatal": 0, "unknown": 0}
        repairable = 0
        for rf in files:
            dmg = getattr(rf, 'damage_report', None)
            if dmg and hasattr(dmg, 'damage_level'):
                counts[dmg.damage_level] = counts.get(dmg.damage_level, 0) + 1
                if dmg.repairable:
                    repairable += 1
            else:
                counts["unknown"] += 1

        # Build summary
        parts = []
        for level, icon in [("healthy", "✅"), ("minor", "⚠️"),
                             ("moderate", "🟡"), ("severe", "🔴"),
                             ("fatal", "💀")]:
            if counts.get(level, 0) > 0:
                parts.append(f"{icon} {level}: {counts[level]}")

        summary = "  |  ".join(parts)
        repair_note = f"  •  🔧 {repairable} repairable" if repairable else ""

        self.status_lbl.configure(
            text=f"🩺 Analysis complete — {summary}{repair_note}")
        self.summary_lbl.configure(
            text=f"🩺 Damage analysis: {summary}{repair_note}")

        if repairable > 0:
            messagebox.showinfo(
                "Damage Analysis Complete",
                f"Analyzed {len(files)} file(s):\n\n"
                + "\n".join(f"  {icon} {level.capitalize()}: {counts[level]}"
                           for level, icon in [("healthy", "✅"), ("minor", "⚠️"),
                                                ("moderate", "🟡"), ("severe", "🔴"),
                                                ("fatal", "💀")]
                           if counts.get(level, 0) > 0)
                + f"\n\n🔧 {repairable} file(s) can be repaired.\n"
                  f"Click 'Repair' to attempt automatic repair.")
        else:
            damaged = sum(counts[k] for k in ("minor", "moderate", "severe", "fatal"))
            if damaged == 0:
                messagebox.showinfo(
                    "Damage Analysis Complete",
                    f"✅ All {len(files)} file(s) are healthy!\n\n"
                    "No damage detected.")
            else:
                messagebox.showinfo(
                    "Damage Analysis Complete",
                    f"Analyzed {len(files)} file(s):\n\n"
                    + "\n".join(f"  {icon} {level.capitalize()}: {counts[level]}"
                               for level, icon in [("healthy", "✅"), ("minor", "⚠️"),
                                                    ("moderate", "🟡"), ("severe", "🔴"),
                                                    ("fatal", "💀")]
                               if counts.get(level, 0) > 0)
                    + "\n\nNo files are repairable.")

    def _repair_selected(self):
        """Attempt to repair damaged selected files."""
        # Combine selections from both tabs
        all_selected = [f for f in self.recovered_files
                        if self._checked.get(id(f), True) or self._workable_checked.get(id(f), False)]
        
        files = [f for f in all_selected
                 if getattr(f, 'damage_report', None)
                 and hasattr(f.damage_report, 'repairable')
                 and f.damage_report.repairable]

        if not files:
            # Check if analysis was done
            unanalyzed = [f for f in all_selected
                          if not getattr(f, 'damage_report', None)]
            if unanalyzed:
                messagebox.showinfo(
                    "Analyze First",
                    "Please run 'Analyze' first to detect damaged files,\n"
                    "then use 'Repair' on repairable files.")
            else:
                messagebox.showinfo(
                    "Nothing to Repair",
                    "No repairable files in selection.\n\n"
                    "Files are either healthy or too damaged to repair.")
            return

        if not messagebox.askyesno(
            "Repair Files",
            f"Attempt to repair {len(files)} damaged file(s)?\n\n"
            "Repairs include:\n"
            "• Fixing corrupted headers\n"
            "• Appending missing end-of-file markers\n"
            "• Fixing CRC checksums\n"
            "• Trimming garbage data\n\n"
            "Original data is preserved — repairs are applied during save."):
            return

        self.status_lbl.configure(
            text=f"🔧 Repairing {len(files)} files...")

        repaired = 0
        failed = 0
        for rf in files:
            try:
                data = self.manager._read_from_device(
                    rf.raw_device_path, rf.offset, rf.size)
                if data:
                    result = repair_file(rf.extension, data, rf.damage_report)
                    rf.repair_result = result
                    if result.success:
                        rf.is_repaired = True
                        rf.damage_report = result.damage_after
                        repaired += 1
                    else:
                        failed += 1
                else:
                    failed += 1
            except Exception as e:
                logger.warning("Repair failed for %s: %s", rf.display_name, e)
                failed += 1

        self._pop_tree()
        self.status_lbl.configure(
            text=f"🔧 Repair complete — ✅ {repaired} repaired, "
                 f"❌ {failed} failed")

        messagebox.showinfo(
            "Repair Complete",
            f"Repair results:\n\n"
            f"  ✅ Repaired: {repaired}\n"
            f"  ❌ Failed: {failed}\n\n"
            f"Repaired files will be saved with fixes applied.")

    # ─── Filters ──────────────────────────────────────────────

    def _apply_filters(self, event=None):
        cv = self.fc_combo.get()
        self._f_cat = None if cv in ("All", "All Types") else cv
        ev = self.fe_combo.get()
        self._f_ext = None if ev == "All" else ev.lstrip(".")
        sv = self.fs_combo.get()
        ranges = {
            "All Sizes": (0, 0), "< 100 KB": (0, 100 * 1024),
            "100 KB – 1 MB": (100 * 1024, 1024 * 1024),
            "1 MB – 10 MB": (1024 * 1024, 10 * 1024 * 1024),
            "10 MB – 100 MB": (10 * 1024 * 1024, 100 * 1024 * 1024),
            "> 100 MB": (100 * 1024 * 1024, 0),
        }
        self._f_smin, self._f_smax = ranges.get(sv, (0, 0))
        hv = self.fh_combo.get()
        health_map = {
            "All": None, "All Files": None,
            "✅ Workable": "workable",
            "❌ Non-Workable": "non-workable",
            "❓ Unverified": "unverified",
        }
        self._f_health = health_map.get(hv)
        self._pop_tree()

    # ─── Actions ──────────────────────────────────────────────

    def _refresh_drives(self):
        self.drives = self.manager.list_drives()
        vals = [d.display_name for d in self.drives]
        if not vals:
            vals = ["No drives — click ⟳"]
        self.drive_combo["values"] = vals
        if vals:
            self.drive_combo.current(0)
            self._on_drive_sel(None)

    def _open_disk_image(self):
        """Open a disk image file (.img, .dd, .raw, .dmg, .iso, .E01) for scanning."""
        path = filedialog.askopenfilename(
            title="Open Disk Image",
            filetypes=[
                ("All Disk Images", "*.img *.dd *.raw *.dmg *.iso *.bin *.E01 *.001"),
                ("Raw Images", "*.img *.dd *.raw *.bin"),
                ("macOS Images", "*.dmg"),
                ("ISO Images", "*.iso"),
                ("Forensic Images", "*.E01 *.001"),
                ("All Files", "*.*"),
            ],
        )
        if not path:
            return

        # Create a DriveInfo for the disk image
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0

        img_drive = DriveInfo(
            device_path=path,
            mount_point="",
            label=os.path.basename(path),
            filesystem="Image",
            total_size=size,
            free_size=size,  # Scan entire image
            is_removable=False,
            drive_type="Disk Image",
            is_mounted=False,
            bus_protocol="File",
        )

        # Add to drives list and select it
        self.drives.append(img_drive)
        vals = list(self.drive_combo["values"]) if self.drive_combo["values"] else []
        vals.append(img_drive.display_name)
        self.drive_combo["values"] = vals
        self.drive_combo.current(len(vals) - 1)
        self._on_drive_sel(None)

    def _on_drive_sel(self, event):
        idx = self.drive_combo.current()
        if 0 <= idx < len(self.drives):
            d = self.drives[idx]
            self.selected_drive = d
            mount_txt = d.mount_point if d.mount_point else "(unmounted)"
            dtype_txt = f"  •  Type: {d.drive_type}" if d.drive_type else ""
            bus_txt = f"  [{d.bus_protocol}]" if d.bus_protocol else ""
            self.drive_info.configure(
                text=f"Device: {d.device_path}\nMount: {mount_txt}\n"
                     f"Size: {d.size_human}  •  FS: {d.filesystem}\n"
                     f"Free: {d.free_human}{dtype_txt}{bus_txt}")

            # Detect SSD/TRIM in background
            self.health_lbl.configure(text="🔍 Checking drive type...", foreground=FG_DIM)
            detect_path = d.mount_point or d.device_path
            threading.Thread(
                target=self._detect_health_bg, args=(d, detect_path), daemon=True
            ).start()
        else:
            self.selected_drive = None
            self.drive_info.configure(text="No drive selected")
            self.health_lbl.configure(text="")
            self._drive_health = None

    def _detect_health_bg(self, drive, path):
        """Background thread: detect SSD/TRIM for selected drive."""
        try:
            health = detect_drive_health(path)
            # Propagate drive_type from DriveInfo if detected there
            if drive.drive_type and health.drive_type == "Unknown":
                health.drive_type = drive.drive_type
                _assess_recovery_with_type(health)
            self._drive_health = health
            self.root.after(0, self._show_health, health)
        except Exception:
            self._drive_health = None
            self.root.after(0, lambda: self.health_lbl.configure(
                text="ℹ️ Drive type unknown", foreground=FG_DIM))

    def _show_health(self, health: DriveHealthInfo):
        """Update UI with drive health / TRIM info."""
        conf = health.recovery_confidence.upper()
        model = health.model or ""
        dtype = health.drive_type or "Drive"

        if health.is_ssd_with_trim:
            self.health_lbl.configure(
                text=f"🛑 {dtype} + TRIM ENABLED\n"
                     f"Recovery: VERY UNLIKELY\n"
                     f"TRIM erases deleted data at hardware level\n{model}",
                foreground=FG_ERROR,
            )
        elif health.is_external and health.is_ssd:
            # External SSDs (USB, Thunderbolt, FireWire) — TRIM rarely passes
            conn = health.connection_type or "USB"
            self.health_lbl.configure(
                text=f"⚡ {dtype}\n"
                     f"TRIM unlikely via {conn} enclosure\n"
                     f"Recovery: {conf}\n{model}",
                foreground=FG_WARN,
            )
        elif health.is_ssd:
            trim_txt = "On" if health.trim_enabled else "Off"
            self.health_lbl.configure(
                text=f"⚠️ {dtype} detected\n"
                     f"TRIM: {trim_txt}  •  Recovery: {conf}",
                foreground=FG_WARN,
            )
        elif health.is_hdd:
            self.health_lbl.configure(
                text=f"✅ {health.drive_type} — Best for recovery\n"
                     f"Recovery: {conf}\n{model}",
                foreground=FG_SUCCESS,
            )
        elif conf == "high":
            # USB, SD card, disk image, virtual — high confidence
            dtype = health.drive_type or "Drive"
            self.health_lbl.configure(
                text=f"✅ {dtype}\nRecovery: {conf}\n{model}",
                foreground=FG_SUCCESS,
            )
        elif conf in ("medium", "medium-high"):
            dtype = health.drive_type or "Drive"
            self.health_lbl.configure(
                text=f"🔌 {dtype}\nRecovery: {conf.upper()}\n{model}",
                foreground=FG_WARN,
            )
        else:
            self.health_lbl.configure(
                text=f"ℹ️ {health.drive_type}\n"
                     f"Recovery: {conf}",
                foreground=FG_DIM,
            )

    def _start_scan(self):
        if not self.selected_drive:
            messagebox.showwarning("No Drive", "Select a drive first.")
            return
        cats = {c for c, v in self.category_vars.items() if v.get()}
        if not cats:
            messagebox.showwarning("No Types", "Select at least one type.")
            return

        # ── SSD + TRIM warning ──
        if self._drive_health and self._drive_health.is_ssd_with_trim:
            proceed = messagebox.askyesno(
                "🛑 SSD + TRIM Detected",
                f"{self._drive_health.recovery_warning}\n\n"
                "Do you want to scan anyway?\n"
                "(Very unlikely to find deleted files)",
                icon="warning",
            )
            if not proceed:
                return

        # Clear
        self.tree.delete(*self.tree.get_children())
        self.cat_tree.delete(*self.cat_tree.get_children())
        self.recovered_files.clear()
        self._tree_map.clear()
        self._cat_ids.clear()
        self._checked.clear()
        self._selected_group = None
        self._f_cat = self._f_ext = None
        self._f_smin = self._f_smax = 0
        self._f_health = None
        self.fc_combo.current(0)
        self.fe_combo.current(0)
        self.fs_combo.current(0)
        self.fh_combo.current(0)

        self.status_lbl.configure(text="⚡ Starting raw sector scan...")
        self.mode_lbl.configure(text="")
        self.pbar["value"] = 0
        self.scan_btn.pack_forget()
        self.cancel_btn.pack(fill=tk.X, ipady=5)
        self.s_found.configure(text="Found: 0")
        self.s_speed.configure(text="")
        self.s_eta.configure(text="")
        self.s_pct.configure(text="")

        self.manager.set_callbacks(
            on_progress=self._on_progress,
            on_file_found=self._on_file_found,
            on_scan_complete=self._on_scan_complete,
        )

        self.manager.start_scan(
            device_path=self.selected_drive.mount_point or self.selected_drive.device_path,
            output_dir="",
            categories=cats,
            preview_only=True,
        )

    def _on_file_found(self, rf):
        self.root.after(0, self._add_file, rf)

    def _add_file(self, rf):
        self.recovered_files.append(rf)
        self._checked[id(rf)] = True
        n = len(self.recovered_files)
        if n <= 10 or n % 5 == 0:
            self._pop_cat_tree()
            self._update_ext_combo(self.recovered_files)

    def _on_scan_complete(self, session):
        self.root.after(0, self._finalize, session)

    def _finalize(self, session):
        self.cancel_btn.pack_forget()
        self.scan_btn.pack(fill=tk.X, ipady=5)
        self.pbar["value"] = 100

        self._pop_tree()
        total = len(self.recovered_files)

        # Show scan mode in finalization
        mode_tag = ""
        if session.scan_mode == "forensic":
            free_pct = (session.free_clusters / session.total_clusters * 100) if session.total_clusters else 0
            mode_tag = f"🔬 Forensic ({session.fs_type.upper()}) — {free_pct:.0f}% unallocated"
            self.mode_lbl.configure(
                text=(
                    f"🔬 Forensic scan ({session.fs_type.upper()})  •  "
                    f"Scanned {_fmt(session.free_bytes)} unallocated space  •  "
                    f"{session.free_clusters:,} free / {session.total_clusters:,} total clusters"
                ),
                foreground=FG_SUCCESS,
            )
        else:
            mode_tag = "⚡ Brute-force"
            self.mode_lbl.configure(
                text="⚡ Brute-force scan (no filesystem bitmap available)",
                foreground=FG_WARN,
            )

        if session.was_cancelled:
            self.status_lbl.configure(text=f"⏹ Cancelled. Found {total}.")
            self.summary_lbl.configure(text=f"Cancelled — {total} file(s).")
            if total > 0:
                self._start_deep_validation()
        elif total > 0:
            cats = defaultdict(int)
            sz = 0
            tsk_count = 0
            carved_count = 0
            for f in self.recovered_files:
                cats[f.category] += 1
                sz += f.size
                if getattr(f, 'source', 'carved') == 'tsk':
                    tsk_count += 1
                else:
                    carved_count += 1
            parts = [f"{CAT_ICONS.get(c, '')} {c}: {n}" for c, n in sorted(cats.items())]
            # Source breakdown
            src_parts = []
            if tsk_count > 0:
                src_parts.append(f"🔍 TSK: {tsk_count}")
            if carved_count > 0:
                src_parts.append(f"⛏ Carved: {carved_count}")
            src_tag = "  •  " + "  |  ".join(src_parts) if src_parts else ""
            # Performance info
            perf_parts = []
            if self.manager.progress.using_mmap:
                perf_parts.append("mmap")
            if self.manager.progress.skipped_empty_bytes > 0:
                perf_parts.append(f"skipped {self.manager.progress.skipped_empty_bytes / (1024*1024):.0f} MB empty")
            if self.manager.progress.drive_type:
                perf_parts.append(self.manager.progress.drive_type)
            perf_tag = f"  [{', '.join(perf_parts)}]" if perf_parts else ""
            self.summary_lbl.configure(
                text=f"✅ {total} deleted files ({_fmt(sz)})  •  "
                     + "  |  ".join(parts)
                     + f"{src_tag}  •  {mode_tag}{perf_tag}  •  Verifying workability...")
            self.status_lbl.configure(
                text=f"✅ {mode_tag} — Found {total}. Now verifying which files truly work...")

            # Auto-start deep validation
            self._start_deep_validation()
        else:
            self.summary_lbl.configure(text="No deleted files found.")
            self.status_lbl.configure(text=f"{mode_tag} — Scan complete. No deleted files found.")

            # Provide TRIM-specific explanation if applicable
            if self._drive_health and self._drive_health.is_ssd_with_trim:
                messagebox.showinfo(
                    "Scan Complete — SSD + TRIM",
                    "No deleted photos or videos were found.\n\n"
                    f"⚠️ This drive is an {self._drive_health.drive_type} "
                    f"with TRIM ENABLED.\n\n"
                    "TRIM erases deleted blocks at the hardware level.\n"
                    "No software can recover TRIM'd data — this is a\n"
                    "physical limitation, not a software one.\n\n"
                    "This is expected behavior.")
            else:
                messagebox.showinfo(
                    "Scan Complete",
                    "No deleted photos or videos were found.\n\n"
                    "Tips:\n"
                    "• Run with sudo for raw disk access\n"
                    "• Ensure the correct drive is selected\n"
                    "• Data may have been overwritten\n"
                    "• SSD + TRIM makes recovery impossible")

    def _start_deep_validation(self):
        """Auto-validate all recovered files to separate truly workable from non-workable."""
        files = list(self.recovered_files)
        if not files:
            return

        self.scan_btn.configure(state="disabled")
        self._validation_paused.set()  # Ensure not paused
        self._validation_cancelled = False
        self.pause_btn.configure(text="⏸  Pause Verification")
        self.pause_btn.pack(fill=tk.X, ipady=4, pady=(5, 0))
        self.status_lbl.configure(
            text=f"🔍 Verifying {len(files)} files — separating workable from non-workable...")
        self.pbar["value"] = 0

        def do_validate():
            workable = 0
            nonworkable = 0
            for i, rf in enumerate(files):
                # Wait here if paused
                self._validation_paused.wait()
                # Check if cancelled
                if self._validation_cancelled:
                    self.root.after(0, self._validation_done, workable, nonworkable)
                    return

                try:
                    ok = self.manager.deep_validate_file(rf)
                    rf.is_validated = True
                    if ok:
                        workable += 1
                    else:
                        nonworkable += 1
                except Exception as e:
                    logger.warning("Deep validation error for %s: %s",
                                   rf.display_name, e)
                    rf.is_truly_workable = False
                    rf.is_validated = True
                    rf.workability_reason = f"Error: {e}"
                    nonworkable += 1

                # Update UI periodically
                if (i + 1) % 3 == 0 or i == len(files) - 1:
                    pct = ((i + 1) / len(files)) * 100
                    self.root.after(0, lambda p=pct, c=i+1, w=workable, nw=nonworkable:
                        self._update_validation_progress(p, c, len(files), w, nw))

            self.root.after(0, self._validation_done, workable, nonworkable)

        threading.Thread(target=do_validate, daemon=True).start()

    def _toggle_pause_validation(self):
        """Toggle pause/resume for the deep validation process."""
        if self._validation_paused.is_set():
            # Currently running → pause
            self._validation_paused.clear()
            self.pause_btn.configure(text="▶  Resume Verification")
            self.status_lbl.configure(
                text=self.status_lbl.cget("text").replace("🔍", "⏸") + "  (PAUSED)")
        else:
            # Currently paused → resume
            self._validation_paused.set()
            self.pause_btn.configure(text="⏸  Pause Verification")

    def _cancel_validation(self):
        """Cancel the ongoing validation."""
        self._validation_cancelled = True
        self._validation_paused.set()  # Unpause so thread can exit

    def _update_validation_progress(self, pct, current, total, workable, nonworkable):
        """Update UI during deep validation."""
        self.pbar["value"] = pct
        self.s_pct.configure(text=f"{pct:.0f}%")
        self.status_lbl.configure(
            text=f"🔍 Verifying files ({current}/{total})  •  "
                 f"✅ {workable} workable  •  ❌ {nonworkable} non-workable")
        self.s_found.configure(text=f"✅ {workable}  ❌ {nonworkable}")

        # Live-refresh the Truly Workable tab as files are identified
        self._pop_workable_cat_tree()
        # Auto-show all workable files in the workable file list
        workable_files = [f for f in self.recovered_files
                          if self._workability_of(f) == 'workable']
        if workable_files:
            self._pop_workable_tree(workable_files)

        # Update the tab title with live count
        tab_id = self.results_notebook.index(0)  # workable tab is first
        self.results_notebook.tab(tab_id, text=f"✅ Truly Workable ({workable})")

    def _validation_done(self, workable, nonworkable):
        """Called when deep validation completes."""
        self.scan_btn.configure(state="normal")
        self.pause_btn.pack_forget()
        self._validation_paused.set()
        self._validation_cancelled = False
        self.pbar["value"] = 100
        total = len(self.recovered_files)

        # Auto-deselect non-workable files
        for rf in self.recovered_files:
            if getattr(rf, 'is_validated', False) and not getattr(rf, 'is_truly_workable', False):
                self._checked[id(rf)] = False

        self._pop_tree()

        # Update workable tab title with final count
        tab_id = self.results_notebook.index(0)
        self.results_notebook.tab(tab_id, text=f"✅ Truly Workable ({workable})")

        # Auto-switch to the Truly Workable tab if there are workable files
        if workable > 0:
            self.results_notebook.select(0)

        self.status_lbl.configure(
            text=f"✅ Verification complete — {workable} workable, "
                 f"{nonworkable} non-workable out of {total} files")
        self.summary_lbl.configure(
            text=f"✅ {workable} truly workable files  •  "
                 f"❌ {nonworkable} non-workable (auto-deselected)  •  "
                 f"{total} total  •  Select workable files → Save")

        if nonworkable > 0 and workable > 0:
            messagebox.showinfo(
                "Verification Complete",
                f"Verified {total} file(s):\n\n"
                f"  ✅ {workable} truly workable files\n"
                f"  ❌ {nonworkable} non-workable files\n\n"
                f"Non-workable files have been auto-deselected.\n"
                f"Only workable files will be saved.\n\n"
                f"You can still manually select non-workable files\n"
                f"if you want to try saving them anyway.")
        elif workable == 0:
            messagebox.showwarning(
                "No Workable Files",
                f"None of the {total} recovered file(s) passed\n"
                f"deep validation.\n\n"
                f"All files appear to be corrupted, truncated,\n"
                f"or contain garbage data.\n\n"
                f"You can still try saving them, but they likely\n"
                f"won't open in any application.")

    def _cancel_scan(self):
        self.manager.cancel_scan()
        self.cancel_btn.pack_forget()
        self.scan_btn.pack(fill=tk.X, ipady=5)
        self.pbar["value"] = 0
        self.status_lbl.configure(text="Cancelled.")

    def _on_progress(self, p):
        self.root.after(0, self._update_progress, p)

    def _update_progress(self, p):
        self.status_lbl.configure(text=p.status_message)
        self.pbar["value"] = p.progress_percent
        self.s_pct.configure(text=f"{p.progress_percent:.1f}%")
        if p.speed_mbps > 0:
            self.s_speed.configure(text=f"{p.speed_mbps:.1f} MB/s")
        eta = p.eta_seconds
        if eta > 0:
            if eta < 60:
                es = f"{eta:.0f}s"
            elif eta < 3600:
                es = f"{eta / 60:.1f}m"
            else:
                es = f"{eta / 3600:.1f}h"
            self.s_eta.configure(text=f"ETA: {es}")
        self.s_found.configure(text=f"Found: {p.files_found}")

        # Update scan mode indicator
        if p.scan_mode == "forensic" and p.fs_type:
            free_pct = (p.free_clusters / p.total_clusters * 100) if p.total_clusters else 0
            self.mode_lbl.configure(
                text=(
                    f"🔬 Forensic Mode: {p.fs_type.upper()} bitmap  •  "
                    f"Scanning {_fmt(p.free_bytes)} unallocated space "
                    f"({free_pct:.1f}% of disk, {p.free_ranges_count} free ranges)"
                    + (f"  •  mmap" if p.using_mmap else "")
                    + (f"  •  Skipped {p.skipped_empty_bytes / (1024*1024):.0f} MB empty" if p.skipped_empty_bytes > 0 else "")
                ),
                foreground=FG_SUCCESS,
            )
        elif p.scan_mode == "brute-force" and p.is_scanning:
            perf_parts = []
            if p.using_mmap:
                perf_parts.append("mmap")
            if p.skipped_empty_bytes > 0:
                perf_parts.append(f"skipped {p.skipped_empty_bytes / (1024*1024):.0f} MB empty")
            if p.drive_type:
                perf_parts.append(p.drive_type)
            if p.trim_enabled:
                perf_parts.append("⚠️ TRIM ON")
            perf = f"  •  {', '.join(perf_parts)}" if perf_parts else ""
            self.mode_lbl.configure(
                text=f"⚡ Brute-Force Mode: scanning entire disk (no filesystem bitmap detected){perf}",
                foreground=FG_WARN,
            )

    # ─── Save ─────────────────────────────────────────────────

    def _browse_output(self):
        p = filedialog.askdirectory(
            title="Choose output folder",
            initialdir=self._output_dir if os.path.isdir(self._output_dir)
                       else os.path.expanduser("~"))
        if p:
            self._output_dir = p
            self.out_lbl.configure(text=self._short(p, 50))

    def _save_selected(self):
        # Combine selections from both tabs
        # _checked defaults True, _workable_checked defaults False
        files = [f for f in self.recovered_files
                 if self._checked.get(id(f), True) or self._workable_checked.get(id(f), False)]
        
        if not files:
            messagebox.showinfo("Nothing", "No files selected.")
            return

        # Verify output directory is writable
        try:
            os.makedirs(self._output_dir, exist_ok=True)
        except OSError as e:
            messagebox.showerror(
                "Error",
                f"Cannot create output directory:\n{self._output_dir}\n\n{e}"
            )
            return

        # Check that files have the raw device path for re-carving
        valid_files = [f for f in files if f.raw_device_path and f.size > 0]
        if not valid_files:
            messagebox.showerror(
                "Error",
                "Selected files have no raw device path.\n\n"
                "This usually means the disk was ejected or\n"
                "the scan did not record the device path."
            )
            return

        # Verify the raw device is still accessible
        device = valid_files[0].raw_device_path
        if not os.path.exists(device):
            messagebox.showerror(
                "Error",
                f"Raw device no longer accessible:\n{device}\n\n"
                "Make sure the drive is still connected and\n"
                "the app is running with sudo."
            )
            return

        sz = sum(f.size for f in valid_files)
        if not messagebox.askyesno(
            "Save",
            f"Save {len(valid_files)} file(s) ({_fmt(sz)}) to:\n{self._output_dir}"):
            return

        # Disable save button during save
        self.save_btn.configure(state="disabled")

        # Open the dedicated save-progress dialog
        dlg = SaveProgressDialog(self.root, len(valid_files), self._output_dir)

        def do():
            def prog(current, total, saved_ok=None, file_size=0, file_ext=""):
                elapsed = time.time() - dlg.start_time
                if saved_ok is True:
                    dlg.ok_count += 1
                    dlg.bytes_written += file_size
                elif saved_ok is False:
                    dlg.fail_count += 1

                speed = dlg.bytes_written / elapsed / (1024 * 1024) if elapsed > 0 else 0
                remaining = total - current
                eta = (elapsed / current) * remaining if current > 0 else 0
                pct = (current / total) * 100 if total else 100

                self.root.after(0, lambda p=pct, c=current, t=total,
                                ok=dlg.ok_count, fl=dlg.fail_count,
                                sp=speed, et=eta,
                                wr=_fmt(dlg.bytes_written),
                                ext=file_ext:
                    dlg.update_progress(p, c, t, ok, fl, sp, et, wr, ext))

            saved = self.manager.save_selected_files(
                valid_files, self._output_dir, prog)
            self.root.after(0, lambda s=saved: self._save_done(s, len(valid_files), dlg))

        threading.Thread(target=do, daemon=True).start()

    def _save_done(self, saved, total_attempted, dlg: "SaveProgressDialog"):
        self.save_btn.configure(state="normal")
        self._pop_tree()

        n = len(saved)
        total_sz = _fmt(sum(f.size for f in saved))
        elapsed = time.time() - dlg.start_time

        # Collect integrity & repair statistics
        verified_ok = 0
        verified_fail = 0
        repaired_count = 0
        damaged_saved = 0
        for rf in saved:
            ic = getattr(rf, 'integrity_check', None)
            if ic and hasattr(ic, 'passed'):
                if ic.passed:
                    verified_ok += 1
                else:
                    verified_fail += 1
            if getattr(rf, 'is_repaired', False):
                repaired_count += 1
            dmg = getattr(rf, 'damage_report', None)
            if dmg and hasattr(dmg, 'is_damaged') and dmg.is_damaged:
                damaged_saved += 1

        # Update the dialog to "done" state with integrity info
        integrity_text = ""
        if verified_ok > 0 or verified_fail > 0:
            integrity_text = f"  •  ✅ {verified_ok} verified"
            if verified_fail > 0:
                integrity_text += f"  •  ⚠️ {verified_fail} integrity warnings"
        if repaired_count > 0:
            integrity_text += f"  •  🔧 {repaired_count} repaired"

        dlg.set_done(n, total_attempted, total_sz, elapsed,
                     verified_ok=verified_ok, verified_fail=verified_fail,
                     repaired=repaired_count)

        if n == 0:
            messagebox.showerror(
                "Save Failed",
                f"Could not save any of the {total_attempted} selected file(s).\n\n"
                f"Output directory: {self._output_dir}\n\n"
                "Possible causes:\n"
                "• Drive was ejected during save\n"
                "• Permission denied (try running with sudo)\n"
                "• Disk I/O error\n\n"
                "Check the terminal for detailed error messages.",
                parent=dlg.top,
            )
        elif n < total_attempted:
            messagebox.showwarning(
                "Partial Save",
                f"Saved {n} out of {total_attempted} file(s) ({total_sz}).\n"
                f"Time: {elapsed:.1f}s\n\n"
                f"{total_attempted - n} file(s) failed to save.\n"
                + (f"🔧 {repaired_count} file(s) were auto-repaired.\n" if repaired_count else "")
                + (f"✅ {verified_ok} passed integrity verification.\n" if verified_ok else "")
                + (f"⚠️ {verified_fail} had integrity warnings.\n" if verified_fail else "")
                + f"\nCheck the terminal for error details.\n\n{self._output_dir}",
                parent=dlg.top,
            )
        else:
            repair_note = f"\n🔧 {repaired_count} file(s) auto-repaired." if repaired_count else ""
            verify_note = ""
            if verified_ok == n:
                verify_note = f"\n🔒 All {n} files passed integrity verification."
            elif verified_fail > 0:
                verify_note = (f"\n✅ {verified_ok} verified OK"
                               f"\n⚠️ {verified_fail} had integrity warnings")
            messagebox.showinfo(
                "Done",
                f"✅ Saved {n} file(s)!\n\n"
                f"Total size: {total_sz}\n"
                f"Time: {elapsed:.1f}s"
                f"{repair_note}{verify_note}\n\n"
                f"{self._output_dir}",
                parent=dlg.top,
            )

    # ─── Export ───────────────────────────────────────────────

    def _export_csv(self):
        if not self.manager.current_session:
            messagebox.showinfo("Info", "No results to export.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="recovery_report.csv")
        if p:
            self.manager.export_report_csv(p)
            messagebox.showinfo("Exported", f"Saved to {p}")

    def _export_json(self):
        if not self.manager.current_session:
            messagebox.showinfo("Info", "No results to export.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile="recovery_report.json")
        if p:
            self.manager.export_report_json(p)
            messagebox.showinfo("Exported", f"Saved to {p}")

    # ─── Utilities ────────────────────────────────────────────

    @staticmethod
    def _short(path, mx=40):
        if len(path) <= mx:
            return path
        return path[:15] + "..." + path[-(mx - 18):]


# ─── Save Progress Dialog (Toplevel) ─────────────────────────

class SaveProgressDialog:
    """Dedicated popup window showing save progress."""

    def __init__(self, parent: tk.Tk, total_files: int, output_dir: str):
        self.start_time = time.time()
        self.ok_count = 0
        self.fail_count = 0
        self.bytes_written = 0
        self._total = total_files

        self.top = tk.Toplevel(parent)
        self.top.title("💾 Saving Files…")
        self.top.configure(bg=BG_PANEL)
        self.top.transient(parent)

        # Prevent closing during save
        self.top.protocol("WM_DELETE_WINDOW", lambda: None)

        # ── Build all widgets inside a container frame ──
        container = tk.Frame(self.top, bg=BG_PANEL)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        # Header
        tk.Label(container, text="💾  Saving Recovered Files",
                 bg=BG_PANEL, fg=FG_ACCENT,
                 font=(FONT, 14, "bold")).pack(anchor=tk.W)
        tk.Label(container, text=f"To: {self._short(output_dir, 55)}",
                 bg=BG_PANEL, fg=FG_DIM,
                 font=(FONT, 10)).pack(anchor=tk.W, pady=(2, 12))

        # Progress bar
        self.pbar = ttk.Progressbar(container, orient=tk.HORIZONTAL,
                                     mode="determinate",
                                     style="Custom.Horizontal.TProgressbar",
                                     length=470)
        self.pbar.pack(fill=tk.X, pady=(0, 8))

        # Percent + file counter
        row1 = tk.Frame(container, bg=BG_PANEL)
        row1.pack(fill=tk.X)
        self.lbl_pct = tk.Label(row1, text="0%", bg=BG_PANEL, fg=FG_TEXT,
                                 font=(FONT, 13, "bold"))
        self.lbl_pct.pack(side=tk.LEFT)
        self.lbl_file = tk.Label(row1, text=f"0 / {total_files}",
                                  bg=BG_PANEL, fg=FG_TEXT, font=(FONT, 11))
        self.lbl_file.pack(side=tk.RIGHT)

        # Current file type
        self.lbl_current = tk.Label(container, text="Preparing…",
                                     bg=BG_PANEL, fg=FG_DIM, font=(FONT, 10))
        self.lbl_current.pack(anchor=tk.W, pady=(10, 0))

        # Stats row: speed | eta
        row2 = tk.Frame(container, bg=BG_PANEL)
        row2.pack(fill=tk.X, pady=(8, 0))
        self.lbl_speed = tk.Label(row2, text="Speed: —", bg=BG_PANEL,
                                   fg=FG_DIM, font=(FONT, 10))
        self.lbl_speed.pack(side=tk.LEFT)
        self.lbl_eta = tk.Label(row2, text="ETA: —", bg=BG_PANEL,
                                 fg=FG_DIM, font=(FONT, 10))
        self.lbl_eta.pack(side=tk.LEFT, padx=(30, 0))

        # OK / fail counters
        row3 = tk.Frame(container, bg=BG_PANEL)
        row3.pack(fill=tk.X, pady=(10, 0))
        self.lbl_ok = tk.Label(row3, text="✅ Saved: 0", bg=BG_PANEL,
                                fg=FG_SUCCESS, font=(FONT, 11))
        self.lbl_ok.pack(side=tk.LEFT)
        self.lbl_fail = tk.Label(row3, text="", bg=BG_PANEL,
                                  fg=FG_ERROR, font=(FONT, 11))
        self.lbl_fail.pack(side=tk.LEFT, padx=(20, 0))
        self.lbl_size = tk.Label(row3, text="", bg=BG_PANEL,
                                  fg=FG_DIM, font=(FONT, 10))
        self.lbl_size.pack(side=tk.RIGHT)

        # Integrity / repair row
        row4 = tk.Frame(container, bg=BG_PANEL)
        row4.pack(fill=tk.X, pady=(6, 0))
        self.lbl_integrity = tk.Label(row4, text="", bg=BG_PANEL,
                                       fg=FG_DIM, font=(FONT, 10))
        self.lbl_integrity.pack(side=tk.LEFT)
        self.lbl_repaired = tk.Label(row4, text="", bg=BG_PANEL,
                                      fg=FG_DIM, font=(FONT, 10))
        self.lbl_repaired.pack(side=tk.LEFT, padx=(20, 0))

        # Buttons
        btn_frame = tk.Frame(container, bg=BG_PANEL)
        btn_frame.pack(fill=tk.X, pady=(18, 0))

        self.btn_open = ttk.Button(btn_frame, text="📂  Open Folder",
                                    command=lambda: self._open_folder(output_dir),
                                    style="Secondary.TButton", state="disabled")
        self.btn_open.pack(side=tk.LEFT)

        self.btn_close = ttk.Button(btn_frame, text="Close",
                                     command=self.top.destroy,
                                     style="Secondary.TButton", state="disabled")
        self.btn_close.pack(side=tk.RIGHT)

        self._output_dir = output_dir

        # Set geometry and centre on parent AFTER packing widgets
        self.top.update_idletasks()
        w, h = 520, 390
        px = parent.winfo_x() + (parent.winfo_width() - w) // 2
        py = parent.winfo_y() + (parent.winfo_height() - h) // 2
        self.top.geometry(f"{w}x{h}+{px}+{py}")
        self.top.resizable(False, False)
        self.top.lift()
        self.top.focus_force()

    def update_progress(self, pct, current, total, ok, fail, speed, eta, written, ext):
        """Called from the main thread to refresh the dialog."""
        self.pbar["value"] = pct
        self.lbl_pct.configure(text=f"{pct:.0f}%")
        self.lbl_file.configure(text=f"{current} / {total}")
        self.lbl_current.configure(text=f"Saving .{ext} file ({current}/{total})…" if ext else "Saving…")

        self.lbl_ok.configure(text=f"✅ Saved: {ok}")
        if fail > 0:
            self.lbl_fail.configure(text=f"❌ Failed: {fail}")
        self.lbl_size.configure(text=written)

        if speed > 0:
            self.lbl_speed.configure(text=f"Speed: {speed:.1f} MB/s")
        if eta > 0:
            if eta < 60:
                self.lbl_eta.configure(text=f"ETA: ~{eta:.0f}s")
            else:
                self.lbl_eta.configure(text=f"ETA: ~{eta / 60:.1f}m")
        else:
            self.lbl_eta.configure(text="ETA: —")

    def set_done(self, saved, total, size_str, elapsed,
                  verified_ok=0, verified_fail=0, repaired=0):
        """Transition the dialog to a completed state."""
        self.pbar["value"] = 100
        self.lbl_pct.configure(text="100%")
        self.lbl_file.configure(text=f"{total} / {total}")
        self.lbl_speed.configure(text=f"Time: {elapsed:.1f}s")
        self.lbl_eta.configure(text="")

        if saved == total:
            self.lbl_current.configure(
                text=f"✅ All {saved} files saved ({size_str})")
        elif saved == 0:
            self.lbl_current.configure(text=f"❌ Failed to save files")
        else:
            self.lbl_current.configure(
                text=f"⚠️ Saved {saved}/{total} ({size_str})")

        # Show integrity verification results
        if verified_ok > 0 or verified_fail > 0:
            if verified_fail == 0:
                self.lbl_integrity.configure(
                    text=f"🔒 {verified_ok}/{saved} verified OK",
                    fg=FG_SUCCESS)
            else:
                self.lbl_integrity.configure(
                    text=f"🔒 {verified_ok} OK  |  ⚠️ {verified_fail} warnings",
                    fg=FG_WARN)

        if repaired > 0:
            self.lbl_repaired.configure(
                text=f"🔧 {repaired} auto-repaired",
                fg=FG_ACCENT)

        self.btn_open.configure(state="normal")
        self.btn_close.configure(state="normal")
        # Allow closing now
        self.top.protocol("WM_DELETE_WINDOW", self.top.destroy)

    def _open_folder(self, path):
        import subprocess as _sp
        system = platform.system()
        try:
            if system == "Darwin":
                _sp.run(["open", path])
            elif system == "Windows":
                os.startfile(path)
            else:
                _sp.run(["xdg-open", path])
        except Exception:
            pass

    @staticmethod
    def _short(path, mx=40):
        if len(path) <= mx:
            return path
        return path[:15] + "…" + path[-(mx - 18):]


def _fmt(n):
    s = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{s:.1f} TB"


def main():
    root = tk.Tk()
    DataRecoveryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
