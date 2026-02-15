"""
Cerberus Companion App - USB Watchdog Monitor

Features:
- Auto-detection of Cerberus device
- Real-time log with color-coded alerts
- HID Payload analysis with attack pattern detection
- Log filtering and search
- RED TEAM MODE: Payload debugging and DuckyScript export
- Serial command interface
- Timestamp support
- Log export functionality
- Auto-reconnect capability

Requirements: pyserial (`pip install pyserial`)
"""

import sys
import time
import threading
import re
from datetime import datetime
from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from serial import Serial
    from serial.tools import list_ports
except ImportError:
    sys.stderr.write("Missing pyserial. Install with: pip install pyserial\n")
    sys.exit(1)


# ============================================================================
# Configuration
# ============================================================================
TARGET_VID = 0x0951
TARGET_PID = 0x16D5
NAME_HINTS = ("Cerberus", "Kingston", "DataTraveler", "Pico")
BAUDRATE = 115200

# ============================================================================
# Color Theme
# ============================================================================
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_panel": "#16213e",
    "bg_input": "#0f0f1a",
    "bg_redteam": "#2d1f1f",
    "fg_normal": "#e4e4e4",
    "fg_dim": "#7a7a8c",
    "accent": "#4361ee",
    "accent_hover": "#3a56d4",
    "success": "#06d6a0",
    "warning": "#ffd166",
    "danger": "#ef476f",
    "info": "#118ab2",
    "border": "#2a2a4a",
    "redteam": "#ff4444",
    "redteam_dim": "#aa3333",
}

# Alert patterns
ALERT_PATTERNS = [
    (r"\[!!!\].*AUTO", "danger"),   # Automated typing
    (r"\[!!!\].*", "danger"),
    (r"\[!!\].*USB Killer", "danger"),
    (r"\[!!\].*HID", "danger"),
    (r"\[!!\].*", "warning"),
    (r"\[!\].*", "warning"),
    (r"\[\+\+\].*", "success"),
    (r"\[\+\].*", "info"),
    (r"Device attached.*", "info"),
    (r"Device removed.*", "fg_dim"),
    (r"AUTOMATED TYPING", "danger"),
    (r"SUSPICIOUS", "danger"),
]

# Attack patterns
ATTACK_PATTERNS = [
    (r"GUI\+.*r", "WIN+R (Run)", "danger"),
    (r"GUI\+.*x", "WIN+X (Power)", "warning"),
    (r"CTRL\+.*ALT\+.*", "CTRL+ALT combo", "warning"),
    (r"(cmd|powershell|pwsh)", "Shell access", "danger"),
    (r"(Invoke-WebRequest|IWR|wget|curl)", "Download", "danger"),
    (r"(IEX|Invoke-Expression)", "Code exec", "danger"),
    (r"(base64|-enc)", "Encoded cmd", "danger"),
    (r"(net user|net localgroup)", "User manipulation", "danger"),
    (r"(schtasks|reg add)", "Persistence", "danger"),
]

# DuckyScript key mappings (Cerberus firmware -> DuckyScript)
DUCKY_MAP = {
    # Arrow keys
    "<ARROWRIGHT>": "RIGHT", "<ARROWLEFT>": "LEFT",
    "<ARROWDOWN>": "DOWN", "<ARROWUP>": "UP",
    # Navigation
    "<HOME>": "HOME", "<END>": "END",
    "<PAGEUP>": "PAGEUP", "<PAGEDOWN>": "PAGEDOWN",
    "<DEL>": "DELETE", "<DELETE>": "DELETE",
    "<INSERT>": "INSERT",
    # Function keys
    "<F1>": "F1", "<F2>": "F2", "<F3>": "F3", "<F4>": "F4",
    "<F5>": "F5", "<F6>": "F6", "<F7>": "F7", "<F8>": "F8",
    "<F9>": "F9", "<F10>": "F10", "<F11>": "F11", "<F12>": "F12",
    # Special
    "<PAUSE>": "PAUSE", "<PRNT>": "PRINTSCREEN",
    "<SCRLL>": "SCROLLLOCK",
    "<ENTER>": "ENTER",
    "<TAB>": "TAB",
    "<ESCAPE>": "ESCAPE", "<ESC>": "ESCAPE",
    "<SPACE>": "SPACE",
    "<BACKSPACE>": "BACKSPACE",
    # Modifier keys (when pressed alone)
    "<CTRL>": "CTRL", "<ALT>": "ALT", "<WIN>": "GUI",
    "<FN>": "FN",
    # Keypad
    "<KEYPAD_0>": "NUMPAD0", "<KEYPAD_1>": "NUMPAD1",
    "<KEYPAD_2>": "NUMPAD2", "<KEYPAD_3>": "NUMPAD3",
    "<KEYPAD_4>": "NUMPAD4", "<KEYPAD_5>": "NUMPAD5",
    "<KEYPAD_6>": "NUMPAD6", "<KEYPAD_7>": "NUMPAD7",
    "<KEYPAD_8>": "NUMPAD8", "<KEYPAD_9>": "NUMPAD9",
    "<KEYPAD_DIV>": "NUMPAD/", "<KEYPAD_MUL>": "NUMPAD*",
    "<KEYPAD_SUB>": "NUMPAD-", "<KEYPAD_ADD>": "NUMPAD+",
    "<KEYPAD_DECIMAL>": "NUMPAD.",
    # ASCII control characters
    "\r": "ENTER", "\n": "ENTER", "\t": "TAB",
}

FILTER_OPTIONS = [
    ("All", None),
    ("Alerts Only", r"\[!"),
    ("HID Events", r"HID|GUI\+|ALT\+|CTRL\+"),
    ("Devices", r"Device"),
    ("Suspicious", r"\[!!!\]|SUSPICIOUS|AUTO"),
    ("Commands", r"^\["),
]


# ============================================================================
# Utility Functions
# ============================================================================
def pick_port(ports):
    for p in ports:
        if p.vid == TARGET_VID and p.pid == TARGET_PID:
            return p
    for p in ports:
        name = (p.description or "") + " " + (p.manufacturer or "")
        if any(hint.lower() in name.lower() for hint in NAME_HINTS):
            return p
    return None


def get_alert_color(line):
    for pattern, color_key in ALERT_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return COLORS.get(color_key, COLORS["fg_normal"])
    return COLORS["fg_normal"]


# ============================================================================
# Payload Analyzer
# ============================================================================
class PayloadAnalyzer:
    """
    Analyzes HID keystroke data from Cerberus and converts to DuckyScript.

    Cerberus firmware output format:
    - Modifiers are prefix: "CTRL+", "GUI+", "ALT+" (only when pressed)
    - Special keys: "<ENTER>", "<ARROWUP>", "<F1>", etc.
    - Regular characters: printed directly after modifiers
    - No newline between keystrokes (only Enter adds newline)

    Example firmware output:
      "GUI+rpowershell<ENTER>" - GUI+r, then "powershell", then Enter
      "CTRL+c" - CTRL+C
    """

    # Pattern to extract modifier+key combinations
    # Captures: "CTRL+GUI+ALT+r" -> group(1)="CTRL+GUI+ALT+", group(2)="r"
    MODIFIER_KEY_PATTERN = re.compile(
        r'((?:CTRL\+|GUI\+|ALT\+)+)'  # One or more modifiers (non-capturing inner group)
        r'(<[A-Z0-9_]+>|[^\s<])',     # Followed by special key or single non-space char
        re.IGNORECASE
    )

    SPECIAL_KEY_PATTERN = re.compile(r'<[A-Z0-9_]+>', re.IGNORECASE)

    def __init__(self):
        self.reset()

    def reset(self):
        self.keystroke_buffer = ""
        self.keystroke_times = deque(maxlen=100)
        self.detected_patterns = []
        self.raw_events = []

    def add_event(self, modifiers, key):
        """Add a keystroke event with optional modifiers."""
        # Validate key
        if not key or (len(key) == 1 and not key.isprintable() and key not in '\r\n\t'):
            return

        now = time.time()
        self.keystroke_times.append(now)

        # Normalize modifiers to a set
        mods = set()
        if modifiers:
            mod_str = modifiers.upper()
            if "CTRL" in mod_str: mods.add("CTRL")
            if "GUI" in mod_str: mods.add("GUI")
            if "ALT" in mod_str: mods.add("ALT")

        # Clean up key value
        key = key.strip()
        if not key:
            return

        # Determine if it's a special key
        is_special = key.startswith("<") and key.endswith(">")
        special_name = key[1:-1].upper() if is_special else None

        # Store event
        self.raw_events.append({
            "mods": mods,
            "key": key,
            "special": special_name,
            "time": now
        })

        # Update keystroke buffer for pattern detection
        if mods:
            mod_str = "+".join(sorted(mods))
            self.keystroke_buffer += f"[{mod_str}+{key}]"
        elif is_special:
            self.keystroke_buffer += f"[{special_name}]"
        else:
            self.keystroke_buffer += key

        # Limit buffer size
        if len(self.keystroke_buffer) > 1000:
            self.keystroke_buffer = self.keystroke_buffer[-1000:]

    # Lines to completely ignore (status messages, device info, etc.)
    # These patterns match ANYWHERE in the line (not just at the start)
    IGNORE_PATTERNS = [
        # Device lifecycle
        r'Device\s+(attached|removed)',
        r'address\s*=',
        r'instance\s*=',
        r'mounted',
        r'unmounted',
        # HID status messages (not keystroke data)
        r'HID\s+device',
        r'HID\s+Device',
        r'HID\s+Interface',
        r'HID\s+received',
        r'HID\s+Sending',
        r'cannot\s+request',
        r'Protocol\s*=',
        # USB descriptors - match anywhere in line
        r'VID\s*=',
        r'PID\s*=',
        r'ID\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{4}',
        r'Device\s+Descriptor',
        r'bLength',
        r'bDescriptor',
        r'bcdUSB',
        r'bcdDevice',
        r'bDeviceClass',
        r'bDeviceSubClass',
        r'bDeviceProtocol',
        r'bMaxPacketSize',
        r'bNumConfig',
        r'idVendor',
        r'idProduct',
        r'iManufacturer',
        r'iProduct',
        r'iSerialNumber',
        # Mass storage
        r'Mass\s+Device',
        r'CDC\s+Device',
        r'Read\s+LBA',
        r'Write\s+LBA',
        # UI/Status brackets
        r'\[\+\]',
        r'\[!\]',
        r'\[!!\]',
        r'\[!!!\]',
        r'\[\?\]',
        r'^===+',
        r'^---+',
        # UI elements
        r'BTN_',
        r'OLED',
        r'Selftest',
        r'Cerberus\s+(Ready|ready|-)',
        r'^Error:',
        r'SUSPICIOUS',
        r'AUTOMATED\s+TYPING',
        r'keys/sec',
        # Mouse data (coordinates)
        r'\(-?\d+\s+-?\d+\s+-?\d+\)',
        r'MOUSE:',
        # Desc page markers
        r'\[Desc\s+\d+/\d+\]',
    ]

    def is_keystroke_line(self, line):
        """
        Check if a line contains actual keystroke data.

        Keystroke lines from Cerberus firmware are:
        - Short (typically < 100 chars before Enter)
        - Contain printable ASCII or special key markers
        - May have modifier prefixes like GUI+, CTRL+, ALT+
        - Don't match status message patterns
        """
        text = line.strip()
        if not text:
            return False

        # Check against ignore patterns (match anywhere in line)
        for pattern in self.IGNORE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return False

        # Device descriptor lines start with spaces (indented)
        if text.startswith("  "):
            return False

        # Very long lines are not keystrokes (device info dumps)
        if len(text) > 150:
            return False

        # Lines with "=" outside of special keys are usually status messages
        # But allow "=" inside special key markers like <==> for ASCII art
        if "=" in text and "<" not in text and "+" not in text:
            return False

        # Lines with certain punctuation patterns are usually status
        if re.search(r'\d+\s*:\s*\d+', text):  # timestamps like 12:34
            return False

        # Lines with addresses/hex values are status
        if re.search(r'0x[0-9a-fA-F]+', text):
            return False

        # Must look like keystroke data:
        # - Has modifier prefix (CTRL+, GUI+, ALT+) followed by character
        # - Has special key markers (<ENTER>, <F1>, etc.)
        # - Is short printable text (typed characters)

        has_modifier = bool(re.search(r'(CTRL|GUI|ALT)\+.', text, re.IGNORECASE))
        has_special = bool(self.SPECIAL_KEY_PATTERN.search(text))

        # Short printable text without special chars is likely keystrokes
        # Must be mostly printable characters
        printable_count = sum(1 for c in text if c.isprintable())
        is_mostly_printable = printable_count >= len(text) * 0.8

        is_printable_text = len(text) < 80 and is_mostly_printable and all(
            c.isprintable() or c in '<>+\r\n' for c in text
        )

        return has_modifier or has_special or is_printable_text

    def parse_keystroke_line(self, text):
        """
        Parse a line of keystroke output from the firmware.

        The firmware outputs like: "GUI+rpowershell<ENTER>"
        Which means: GUI+r, then p, o, w, e, r, s, h, e, l, l, then <ENTER>

        Returns list of (modifiers, key) tuples.
        """
        events = []
        pos = 0

        while pos < len(text):
            # Try to match modifier+key combination (e.g., "CTRL+GUI+r")
            mod_match = self.MODIFIER_KEY_PATTERN.match(text, pos)
            if mod_match:
                mods_part = mod_match.group(1).upper()  # e.g., "CTRL+GUI+"
                key = mod_match.group(2)               # e.g., "r" or "<ENTER>"

                # Build normalized modifier string
                mods_list = []
                if "CTRL+" in mods_part: mods_list.append("CTRL")
                if "GUI+" in mods_part: mods_list.append("GUI")
                if "ALT+" in mods_part: mods_list.append("ALT")
                mods = "+".join(mods_list)

                events.append((mods, key))
                pos = mod_match.end()
                continue

            # Try to match standalone special key (e.g., "<ENTER>")
            special_match = self.SPECIAL_KEY_PATTERN.match(text, pos)
            if special_match:
                events.append(("", special_match.group(0)))
                pos = special_match.end()
                continue

            # Single character (no modifier)
            char = text[pos]
            if char.isprintable() and char not in '<>+':
                events.append(("", char))
            elif char in '\r\n':
                # Carriage return/newline = Enter key
                events.append(("", "<ENTER>"))
            pos += 1

        return events

    def add_line(self, line):
        """Parse a line of Cerberus output and extract keystrokes."""
        text = line.strip()
        if not text:
            return

        # Filter out non-keystroke lines
        if not self.is_keystroke_line(text):
            return

        # Parse the keystroke line
        events = self.parse_keystroke_line(text)
        for mods, key in events:
            if key and key.strip():
                self.add_event(mods, key)

    def check_patterns(self):
        found = []
        for pattern, name, severity in ATTACK_PATTERNS:
            if re.search(pattern, self.keystroke_buffer, re.IGNORECASE):
                if name not in [p[0] for p in self.detected_patterns]:
                    found.append((name, severity))
                    self.detected_patterns.append((name, severity))
        return found

    def get_typing_speed(self):
        if len(self.keystroke_times) < 2:
            return 0
        times = list(self.keystroke_times)
        duration = times[-1] - times[0]
        return len(times) / duration if duration > 0 else 0

    def is_automated(self, threshold=40):
        return self.get_typing_speed() > threshold

    def get_buffer(self, max_chars=500):
        buf = self.keystroke_buffer[-max_chars:] if len(self.keystroke_buffer) > max_chars else self.keystroke_buffer
        return buf.replace('\r', '↵').replace('\n', '↵').replace('\t', '→')

    def export_duckyscript(self):
        """Export captured payload as valid DuckyScript."""
        if not self.raw_events:
            return "REM No keystrokes captured"

        lines = []
        lines.append("REM Captured by Cerberus USB Watchdog")
        lines.append(f"REM Timestamp: {datetime.now().isoformat()}")
        lines.append(f"REM Total events: {len(self.raw_events)}")
        lines.append("")

        current_string = ""
        last_time = None

        for evt in self.raw_events:
            mods = evt["mods"]
            key = evt["key"]
            special = evt["special"]
            timestamp = evt["time"]

            # Add delay if significant gap (>100ms)
            if last_time and (timestamp - last_time) > 0.1:
                if current_string:
                    lines.append(f"STRING {current_string}")
                    current_string = ""
                delay_ms = int((timestamp - last_time) * 1000)
                if delay_ms > 50:  # Only add meaningful delays
                    lines.append(f"DELAY {delay_ms}")
            last_time = timestamp

            # Handle modifier combinations (GUI+r, CTRL+c, etc.)
            if mods:
                if current_string:
                    lines.append(f"STRING {current_string}")
                    current_string = ""

                # Build DuckyScript modifier command
                # DuckyScript format: GUI r, CTRL ALT DELETE, etc.
                ducky_mods = []
                if "GUI" in mods: ducky_mods.append("GUI")
                if "CTRL" in mods: ducky_mods.append("CTRL")
                if "ALT" in mods: ducky_mods.append("ALT")

                # Get the actual key
                if special:
                    ducky_key = DUCKY_MAP.get(f"<{special}>", special)
                elif key.startswith("<") and key.endswith(">"):
                    ducky_key = DUCKY_MAP.get(key.upper(), key[1:-1])
                else:
                    ducky_key = key.lower()  # DuckyScript uses lowercase for letters

                # Combine: "GUI r" or "CTRL ALT DELETE"
                cmd = " ".join(ducky_mods + [ducky_key])
                lines.append(cmd)

            # Handle special keys without modifiers (<ENTER>, <F1>, etc.)
            elif special:
                if current_string:
                    lines.append(f"STRING {current_string}")
                    current_string = ""
                ducky_key = DUCKY_MAP.get(f"<{special}>", special)
                lines.append(ducky_key)

            # Handle special key notation in key field
            elif key.startswith("<") and key.endswith(">"):
                if current_string:
                    lines.append(f"STRING {current_string}")
                    current_string = ""
                ducky_key = DUCKY_MAP.get(key.upper(), key[1:-1])
                lines.append(ducky_key)

            # Handle regular characters
            else:
                # Check if it's a special char that needs its own command
                if key in DUCKY_MAP:
                    if current_string:
                        lines.append(f"STRING {current_string}")
                        current_string = ""
                    lines.append(DUCKY_MAP[key])
                elif key.isprintable() and len(key) == 1:
                    current_string += key

        # Flush remaining string
        if current_string:
            lines.append(f"STRING {current_string}")

        # Clean up: remove empty lines and merge consecutive DELAYs
        cleaned = []
        for line in lines:
            if line.strip():
                # Merge consecutive DELAYs
                if line.startswith("DELAY ") and cleaned and cleaned[-1].startswith("DELAY "):
                    try:
                        prev_delay = int(cleaned[-1].split()[1])
                        curr_delay = int(line.split()[1])
                        cleaned[-1] = f"DELAY {prev_delay + curr_delay}"
                    except (ValueError, IndexError):
                        cleaned.append(line)
                else:
                    cleaned.append(line)

        return "\n".join(cleaned)


# ============================================================================
# Custom Widgets
# ============================================================================
class StatusIndicator(tk.Canvas):
    def __init__(self, parent, size=12, **kwargs):
        super().__init__(parent, width=size, height=size,
                         bg=COLORS["bg_panel"], highlightthickness=0, **kwargs)
        self.oval = self.create_oval(2, 2, size-2, size-2, fill=COLORS["fg_dim"], outline="")

    def set_state(self, state):
        colors = {"disconnected": COLORS["fg_dim"], "connecting": COLORS["warning"],
                  "connected": COLORS["success"], "error": COLORS["danger"]}
        self.itemconfig(self.oval, fill=colors.get(state, COLORS["fg_dim"]))


class ModernButton(tk.Button):
    def __init__(self, parent, text, command=None, style="primary", **kwargs):
        bg, fg, hover = self._colors(style)
        super().__init__(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=hover, activeforeground=fg, relief="flat",
                         cursor="hand2", font=("Segoe UI", 9), padx=12, pady=4, **kwargs)
        self.default_bg, self.hover_bg = bg, hover
        self.bind("<Enter>", lambda e: self.config(bg=self.hover_bg))
        self.bind("<Leave>", lambda e: self.config(bg=self.default_bg))

    def _colors(self, style):
        if style == "primary": return COLORS["accent"], "#fff", COLORS["accent_hover"]
        if style == "danger": return COLORS["danger"], "#fff", "#d63d5e"
        if style == "redteam": return COLORS["redteam"], "#fff", COLORS["redteam_dim"]
        return COLORS["bg_panel"], COLORS["fg_normal"], COLORS["border"]

    def set_style(self, style):
        bg, fg, hover = self._colors(style)
        self.default_bg, self.hover_bg = bg, hover
        self.config(bg=bg, fg=fg, activebackground=hover)


# ============================================================================
# Main Application
# ============================================================================
class CerberusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cerberus Companion")
        self.geometry("1100x750")
        self.minsize(900, 550)
        self.configure(bg=COLORS["bg_dark"])

        # State
        self.serial = None
        self.stop_event = threading.Event()
        self.reader_thread = None
        self.auto_reconnect = tk.BooleanVar(value=True)
        self.show_timestamps = tk.BooleanVar(value=True)
        self.redteam_mode = tk.BooleanVar(value=False)
        self.filter_ctrl_bug = tk.BooleanVar(value=False)  # Filter Flipper CTRL bug
        self.port_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="All")
        self.cmd_var = tk.StringVar()
        self.all_logs = []
        self.line_count = 0
        self.alert_count = 0
        self.analyzer = PayloadAnalyzer()

        self._build_header()
        self._build_toolbar()
        self._build_main_area()
        self._build_status_bar()
        self._refresh_ports(auto_select=True)
        self._setup_tags()

        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        self.redteam_mode.trace_add("write", lambda *_: self._toggle_redteam())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_header(self):
        header = tk.Frame(self, bg=COLORS["bg_panel"], height=50)
        header.pack(fill="x")
        header.pack_propagate(False)

        left = tk.Frame(header, bg=COLORS["bg_panel"])
        left.pack(side="left", padx=15, pady=8)

        tk.Label(left, text="CERBERUS", font=("Segoe UI", 14, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["fg_normal"]).pack(side="left")
        tk.Label(left, text="  USB Watchdog", font=("Segoe UI", 9),
                 bg=COLORS["bg_panel"], fg=COLORS["fg_dim"]).pack(side="left")

        # Red Team mode toggle
        self.redteam_btn = tk.Checkbutton(
            left, text="RED TEAM", variable=self.redteam_mode,
            font=("Segoe UI", 9, "bold"), bg=COLORS["bg_panel"],
            fg=COLORS["redteam"], selectcolor=COLORS["bg_input"],
            activebackground=COLORS["bg_panel"]
        )
        self.redteam_btn.pack(side="left", padx=(20, 0))

        right = tk.Frame(header, bg=COLORS["bg_panel"])
        right.pack(side="right", padx=15, pady=8)

        self.status_indicator = StatusIndicator(right)
        self.status_indicator.pack(side="left", padx=(0, 6))
        self.status_label = tk.Label(right, text="Disconnected", font=("Segoe UI", 9),
                                      bg=COLORS["bg_panel"], fg=COLORS["fg_dim"])
        self.status_label.pack(side="left")

    def _build_toolbar(self):
        toolbar = tk.Frame(self, bg=COLORS["bg_dark"])
        toolbar.pack(fill="x", padx=15, pady=10)

        conn = tk.Frame(toolbar, bg=COLORS["bg_dark"])
        conn.pack(side="left")

        self.port_combo = ttk.Combobox(conn, textvariable=self.port_var,
                                        state="readonly", width=32, font=("Segoe UI", 9))
        self.port_combo.pack(side="left", padx=(0, 5))
        ModernButton(conn, text="↻", command=self._refresh_ports, style="secondary").pack(side="left", padx=(0, 5))
        self.connect_btn = ModernButton(conn, text="Connect", command=self._toggle_connection, style="primary")
        self.connect_btn.pack(side="left")

        right = tk.Frame(toolbar, bg=COLORS["bg_dark"])
        right.pack(side="right")

        ModernButton(right, text="Save", command=self._save_log, style="secondary").pack(side="right", padx=(5, 0))
        ModernButton(right, text="Clear", command=self._clear_log, style="secondary").pack(side="right", padx=(5, 0))

        tk.Entry(right, textvariable=self.search_var, font=("Segoe UI", 9), width=15,
                 bg=COLORS["bg_input"], fg=COLORS["fg_normal"],
                 insertbackground=COLORS["fg_normal"], relief="flat").pack(side="right", padx=(5, 10), ipady=3)
        tk.Label(right, text="Search:", font=("Segoe UI", 9),
                 bg=COLORS["bg_dark"], fg=COLORS["fg_dim"]).pack(side="right")

        ttk.Combobox(right, textvariable=self.filter_var, state="readonly", width=10,
                     values=[f[0] for f in FILTER_OPTIONS]).pack(side="right", padx=(0, 10))
        tk.Label(right, text="Filter:", font=("Segoe UI", 9),
                 bg=COLORS["bg_dark"], fg=COLORS["fg_dim"]).pack(side="right", padx=(0, 5))

    def _build_main_area(self):
        self.main_container = tk.Frame(self, bg=COLORS["bg_dark"])
        self.main_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Normal mode layout
        self.normal_frame = tk.Frame(self.main_container, bg=COLORS["bg_dark"])
        self._build_normal_view(self.normal_frame)

        # Red Team mode layout
        self.redteam_frame = tk.Frame(self.main_container, bg=COLORS["bg_redteam"])
        self._build_redteam_view(self.redteam_frame)

        self.normal_frame.pack(fill="both", expand=True)

    def _build_normal_view(self, parent):
        paned = tk.PanedWindow(parent, orient="horizontal", bg=COLORS["border"], sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Log
        log_c = tk.Frame(paned, bg=COLORS["border"])
        log_i = tk.Frame(log_c, bg=COLORS["bg_input"])
        log_i.pack(fill="both", expand=True, padx=1, pady=1)

        self.log_text = tk.Text(log_i, wrap="word", state="disabled", font=("Cascadia Code", 9),
                                 bg=COLORS["bg_input"], fg=COLORS["fg_normal"],
                                 selectbackground=COLORS["accent"], relief="flat", padx=10, pady=8)
        scroll = tk.Scrollbar(log_i, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        paned.add(log_c, minsize=400, stretch="always")

        # Status panel (simplified)
        pay_c = tk.Frame(paned, bg=COLORS["border"])
        pay_i = tk.Frame(pay_c, bg=COLORS["bg_panel"])
        pay_i.pack(fill="both", expand=True, padx=1, pady=1)

        # Header
        ph = tk.Frame(pay_i, bg=COLORS["bg_panel"])
        ph.pack(fill="x", padx=10, pady=(10, 5))
        tk.Label(ph, text="HID Monitor", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["fg_normal"]).pack(side="left")
        ModernButton(ph, text="Reset", command=self._reset_analyzer, style="secondary").pack(side="right")

        # Status cards
        status_frame = tk.Frame(pay_i, bg=COLORS["bg_panel"])
        status_frame.pack(fill="x", padx=10, pady=10)

        # Speed card
        speed_card = tk.Frame(status_frame, bg=COLORS["bg_input"], padx=12, pady=8)
        speed_card.pack(fill="x", pady=2)
        tk.Label(speed_card, text="Typing Speed", font=("Segoe UI", 8),
                 bg=COLORS["bg_input"], fg=COLORS["fg_dim"]).pack(anchor="w")
        self.speed_label = tk.Label(speed_card, text="-- k/s", font=("Segoe UI", 14, "bold"),
                                     bg=COLORS["bg_input"], fg=COLORS["fg_normal"])
        self.speed_label.pack(anchor="w")
        self.auto_indicator = tk.Label(speed_card, text="", font=("Segoe UI", 9, "bold"),
                                        bg=COLORS["bg_input"], fg=COLORS["danger"])
        self.auto_indicator.pack(anchor="w")

        # Events card
        events_card = tk.Frame(status_frame, bg=COLORS["bg_input"], padx=12, pady=8)
        events_card.pack(fill="x", pady=2)
        tk.Label(events_card, text="HID Events", font=("Segoe UI", 8),
                 bg=COLORS["bg_input"], fg=COLORS["fg_dim"]).pack(anchor="w")
        self.events_label = tk.Label(events_card, text="0", font=("Segoe UI", 14, "bold"),
                                      bg=COLORS["bg_input"], fg=COLORS["accent"])
        self.events_label.pack(anchor="w")

        # Alerts card
        alerts_card = tk.Frame(status_frame, bg=COLORS["bg_input"], padx=12, pady=8)
        alerts_card.pack(fill="x", pady=2)
        tk.Label(alerts_card, text="Alerts", font=("Segoe UI", 8),
                 bg=COLORS["bg_input"], fg=COLORS["fg_dim"]).pack(anchor="w")
        self.alerts_label = tk.Label(alerts_card, text="0", font=("Segoe UI", 14, "bold"),
                                      bg=COLORS["bg_input"], fg=COLORS["success"])
        self.alerts_label.pack(anchor="w")

        # Flipper CTRL bug workaround
        ctrl_frame = tk.Frame(pay_i, bg=COLORS["bg_panel"])
        ctrl_frame.pack(fill="x", padx=10, pady=(5, 0))
        tk.Checkbutton(ctrl_frame, text="Filter CTRL bug (Flipper)", variable=self.filter_ctrl_bug,
                       font=("Segoe UI", 8), bg=COLORS["bg_panel"], fg=COLORS["warning"],
                       selectcolor=COLORS["bg_input"], activebackground=COLORS["bg_panel"],
                       command=self._on_ctrl_filter_change).pack(anchor="w")

        # Quick Commands (available in normal mode for analysis/debugging)
        qc_normal = tk.LabelFrame(pay_i, text="Quick Commands", font=("Segoe UI", 9),
                                   bg=COLORS["bg_panel"], fg=COLORS["fg_dim"])
        qc_normal.pack(fill="x", padx=10, pady=(10, 10))

        # Only analysis/debugging commands - no red team tools
        cmds_normal = [("STATUS", "STATUS"), ("VERBOSE", "VERBOSE"), ("HEXDUMP", "HEXDUMP"),
                       ("HIDDEBUG", "HIDDEBUG"), ("LAST", "LAST"), ("HELP", "HELP")]
        for i, (label, cmd) in enumerate(cmds_normal):
            btn = tk.Button(qc_normal, text=label, command=lambda c=cmd: self._quick_cmd_normal(c),
                            font=("Segoe UI", 8), bg=COLORS["bg_input"], fg=COLORS["fg_normal"],
                            relief="flat", padx=8, pady=2)
            btn.grid(row=i//3, column=i%3, padx=3, pady=3, sticky="ew")
        qc_normal.grid_columnconfigure(0, weight=1)
        qc_normal.grid_columnconfigure(1, weight=1)
        qc_normal.grid_columnconfigure(2, weight=1)

        paned.add(pay_c, minsize=260)

    def _build_redteam_view(self, parent):
        """Red Team debug mode UI."""
        paned = tk.PanedWindow(parent, orient="horizontal", bg=COLORS["redteam_dim"], sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Left: Log with command input
        left = tk.Frame(paned, bg=COLORS["redteam_dim"])
        left_i = tk.Frame(left, bg=COLORS["bg_input"])
        left_i.pack(fill="both", expand=True, padx=1, pady=1)

        self.rt_log = tk.Text(left_i, wrap="word", state="disabled", font=("Cascadia Code", 9),
                               bg=COLORS["bg_input"], fg=COLORS["fg_normal"],
                               selectbackground=COLORS["redteam"], relief="flat", padx=10, pady=8)
        scroll = tk.Scrollbar(left_i, command=self.rt_log.yview)
        self.rt_log.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.rt_log.pack(side="left", fill="both", expand=True)

        # Command input
        cmd_frame = tk.Frame(left, bg=COLORS["bg_redteam"])
        cmd_frame.pack(fill="x", pady=5)

        tk.Label(cmd_frame, text="CMD>", font=("Cascadia Code", 10, "bold"),
                 bg=COLORS["bg_redteam"], fg=COLORS["redteam"]).pack(side="left", padx=5)

        self.cmd_entry = tk.Entry(cmd_frame, textvariable=self.cmd_var, font=("Cascadia Code", 10),
                                   bg=COLORS["bg_input"], fg=COLORS["redteam"],
                                   insertbackground=COLORS["redteam"], relief="flat")
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=5, ipady=4)
        self.cmd_entry.bind("<Return>", lambda e: self._send_command())

        ModernButton(cmd_frame, text="Send", command=self._send_command, style="redteam").pack(side="right", padx=5)

        paned.add(left, minsize=450, stretch="always")

        # Right: DuckyScript export & tools
        right = tk.Frame(paned, bg=COLORS["redteam_dim"])
        right_i = tk.Frame(right, bg=COLORS["bg_redteam"])
        right_i.pack(fill="both", expand=True, padx=1, pady=1)

        # Header
        rh = tk.Frame(right_i, bg=COLORS["bg_redteam"])
        rh.pack(fill="x", padx=10, pady=10)
        tk.Label(rh, text="RED TEAM TOOLS", font=("Segoe UI", 11, "bold"),
                 bg=COLORS["bg_redteam"], fg=COLORS["redteam"]).pack(side="left")

        # Quick commands
        qc = tk.LabelFrame(right_i, text="Quick Commands", font=("Segoe UI", 9),
                           bg=COLORS["bg_redteam"], fg=COLORS["fg_dim"])
        qc.pack(fill="x", padx=10, pady=5)

        cmds = [("STATUS", "STATUS"), ("VERBOSE", "VERBOSE"), ("HEXDUMP", "HEXDUMP"),
                ("LAST", "LAST"), ("RESET", "RESET"), ("CLEAR", "CLEAR")]
        for i, (label, cmd) in enumerate(cmds):
            btn = tk.Button(qc, text=label, command=lambda c=cmd: self._quick_cmd(c),
                            font=("Segoe UI", 8), bg=COLORS["bg_input"], fg=COLORS["fg_normal"],
                            relief="flat", padx=8, pady=2)
            btn.grid(row=i//3, column=i%3, padx=3, pady=3, sticky="ew")
        qc.grid_columnconfigure(0, weight=1)
        qc.grid_columnconfigure(1, weight=1)
        qc.grid_columnconfigure(2, weight=1)

        # Flipper CTRL bug filter (also available in Red Team mode)
        ctrl_rt_frame = tk.Frame(right_i, bg=COLORS["bg_redteam"])
        ctrl_rt_frame.pack(fill="x", padx=10, pady=(10, 0))
        tk.Checkbutton(ctrl_rt_frame, text="Filter CTRL bug (Flipper)", variable=self.filter_ctrl_bug,
                       font=("Segoe UI", 8), bg=COLORS["bg_redteam"], fg=COLORS["warning"],
                       selectcolor=COLORS["bg_input"], activebackground=COLORS["bg_redteam"],
                       command=self._on_ctrl_filter_change).pack(anchor="w")

        # DuckyScript output
        tk.Label(right_i, text="DuckyScript Export:", font=("Segoe UI", 9),
                 bg=COLORS["bg_redteam"], fg=COLORS["fg_dim"]).pack(anchor="w", padx=10, pady=(10, 2))

        self.ducky_text = tk.Text(right_i, height=12, wrap="word", font=("Cascadia Code", 9),
                                   bg=COLORS["bg_input"], fg=COLORS["warning"], relief="flat", padx=8, pady=6)
        self.ducky_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ducky_text.config(state="disabled")

        # Export buttons
        exp = tk.Frame(right_i, bg=COLORS["bg_redteam"])
        exp.pack(fill="x", padx=10, pady=(0, 10))

        ModernButton(exp, text="Refresh DuckyScript", command=self._refresh_ducky, style="redteam").pack(side="left")
        ModernButton(exp, text="Export .txt", command=self._export_ducky, style="secondary").pack(side="left", padx=5)
        ModernButton(exp, text="Copy", command=self._copy_ducky, style="secondary").pack(side="left")

        paned.add(right, minsize=320)

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=COLORS["bg_panel"], height=32)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        left = tk.Frame(bar, bg=COLORS["bg_panel"])
        left.pack(side="left", padx=15, pady=5)

        tk.Checkbutton(left, text="Auto-reconnect", variable=self.auto_reconnect,
                       font=("Segoe UI", 8), bg=COLORS["bg_panel"], fg=COLORS["fg_dim"],
                       selectcolor=COLORS["bg_input"]).pack(side="left", padx=(0, 10))
        tk.Checkbutton(left, text="Timestamps", variable=self.show_timestamps,
                       font=("Segoe UI", 8), bg=COLORS["bg_panel"], fg=COLORS["fg_dim"],
                       selectcolor=COLORS["bg_input"]).pack(side="left")

        right = tk.Frame(bar, bg=COLORS["bg_panel"])
        right.pack(side="right", padx=15, pady=5)
        self.stats_label = tk.Label(right, text="Lines: 0 | Alerts: 0",
                                     font=("Segoe UI", 8), bg=COLORS["bg_panel"], fg=COLORS["fg_dim"])
        self.stats_label.pack(side="right")

    def _setup_tags(self):
        for widget in [self.log_text, self.rt_log]:
            for name, color in COLORS.items():
                widget.tag_configure(name, foreground=color)
            widget.tag_configure("timestamp", foreground=COLORS["fg_dim"])

    def _toggle_redteam(self):
        if self.redteam_mode.get():
            self.normal_frame.pack_forget()
            self.redteam_frame.pack(fill="both", expand=True)
            self.configure(bg=COLORS["bg_redteam"])
            self._log_rt("=== RED TEAM MODE ACTIVATED ===\n", COLORS["redteam"])
            self._log_rt("Type HELP for commands\n\n", COLORS["fg_dim"])
        else:
            self.redteam_frame.pack_forget()
            self.normal_frame.pack(fill="both", expand=True)
            self.configure(bg=COLORS["bg_dark"])

    def _send_command(self):
        cmd = self.cmd_var.get().strip()
        if cmd and self.serial:
            self._log_rt(f"> {cmd}\n", COLORS["redteam"])
            self.serial.write((cmd + "\r\n").encode())
            self.cmd_var.set("")

    def _quick_cmd(self, cmd):
        if self.serial:
            self._log_rt(f"> {cmd}\n", COLORS["redteam"])
            self.serial.write((cmd + "\r\n").encode())

    def _quick_cmd_normal(self, cmd):
        """Send quick command from normal mode."""
        if self.serial:
            self._log(f"[CMD] > {cmd}\n", COLORS["accent"])
            self.serial.write((cmd + "\r\n").encode())
        else:
            self._log("[!] Not connected\n", COLORS["warning"])

    def _refresh_ducky(self):
        script = self.analyzer.export_duckyscript()
        self.ducky_text.config(state="normal")
        self.ducky_text.delete("1.0", "end")
        self.ducky_text.insert("1.0", script)
        self.ducky_text.config(state="disabled")

    def _export_ducky(self):
        script = self.analyzer.export_duckyscript()
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("DuckyScript", "*.txt"), ("All", "*.*")],
            initialfile=f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            with open(filename, "w") as f:
                f.write(script)
            self._log_rt(f"Exported to {filename}\n", COLORS["success"])

    def _copy_ducky(self):
        self.clipboard_clear()
        self.clipboard_append(self.analyzer.export_duckyscript())
        self._log_rt("DuckyScript copied to clipboard\n", COLORS["success"])

    def _log_rt(self, msg, color=None):
        """Log to red team console."""
        self.rt_log.configure(state="normal")
        tag = None
        if color:
            for name, c in COLORS.items():
                if c == color:
                    tag = name
                    break
        self.rt_log.insert("end", msg, tag)
        self.rt_log.see("end")
        self.rt_log.configure(state="disabled")

    def _reset_analyzer(self):
        self.analyzer.reset()
        self.speed_label.config(text="-- k/s", fg=COLORS["fg_normal"])
        self.auto_indicator.config(text="")
        self.events_label.config(text="0", fg=COLORS["accent"])
        self.alerts_label.config(text="0", fg=COLORS["success"])
        if self.redteam_mode.get():
            self._refresh_ducky()

    def _update_payload_display(self):
        # Update events count
        events = len(self.analyzer.raw_events)
        self.events_label.config(text=str(events))

        # Update speed
        speed = self.analyzer.get_typing_speed()
        self.speed_label.config(text=f"{speed:.1f} k/s")

        if self.analyzer.is_automated():
            self.speed_label.config(fg=COLORS["danger"])
            self.auto_indicator.config(text="AUTOMATED!")
        elif speed > 15:
            self.speed_label.config(fg=COLORS["warning"])
            self.auto_indicator.config(text="SUSPICIOUS")
        else:
            self.speed_label.config(fg=COLORS["fg_normal"])
            self.auto_indicator.config(text="")

        # Update alerts count
        alerts = len(self.analyzer.detected_patterns)
        self.alerts_label.config(text=str(alerts))
        if alerts > 0:
            self.alerts_label.config(fg=COLORS["danger"])
        else:
            self.alerts_label.config(fg=COLORS["success"])

        if self.redteam_mode.get():
            self._refresh_ducky()

    def _check_patterns(self, line):
        # Apply CTRL bug filter before analysis so DuckyScript export is also clean
        filtered_line = self._filter_ctrl_bug_text(line)
        self.analyzer.add_line(filtered_line)
        new = self.analyzer.check_patterns()
        for name, sev in new:
            self._log(f"[ALERT] {name}\n", COLORS[sev])
        if new or "HID" in line.upper() or "GUI+" in line or "ALT+" in line or "CTRL+" in line:
            self._update_payload_display()

    def _filter_ctrl_bug_text(self, text, force=False):
        """Remove spurious CTRL+ prefixes from Flipper Zero bug.

        The Flipper bug sends CTRL modifier with every keystroke, creating patterns like:
        CTRL+pCTRL+oCTRL+wCTRL+eCTRL+r... instead of just "power..."

        It also affects lines with spaces: CTRL+a CTRL+b CTRL+c (each key has CTRL)

        Strategy:
        - If a line has 3+ occurrences of CTRL+, treat entire line as buggy
        - Strip ALL CTRL+ from such lines (except preserve line-initial CTRL+<single-letter>
          which might be a real shortcut like CTRL+r)

        Args:
            text: Input text to filter
            force: If True, apply filter regardless of toggle state
        """
        if not force and not self.filter_ctrl_bug.get():
            return text
        import re

        def filter_line(line):
            """Filter a single line for CTRL bug."""
            # Count CTRL+ occurrences in this line
            ctrl_count = len(re.findall(r'CTRL\+', line, re.IGNORECASE))

            if ctrl_count == 0:
                return line

            # If only 1-2 CTRL+ and they're at the start, might be legitimate shortcuts
            if ctrl_count <= 2:
                # Check if it looks like a legitimate shortcut at start (e.g., "CTRL+r" alone)
                if re.match(r'^(CTRL\+[a-zA-Z]\s*)+$', line.strip(), re.IGNORECASE):
                    return line  # Keep as-is, looks like real shortcuts

                # Check for consecutive CTRL+ (definitely bug)
                if re.search(r'CTRL\+[^\s]CTRL\+', line, re.IGNORECASE):
                    pass  # Fall through to aggressive filtering
                else:
                    return line  # Probably legitimate

            # 3+ CTRL+ occurrences OR consecutive pattern = definitely Flipper bug
            # Strip ALL CTRL+ but try to preserve initial shortcut

            # Check if line starts with a potential real shortcut (CTRL+letter followed by space/text)
            start_match = re.match(r'^(CTRL\+[a-zA-Z])(\s|$)', line, re.IGNORECASE)
            preserved_start = ""
            rest = line

            if start_match:
                # Preserve the initial shortcut
                preserved_start = start_match.group(1)
                rest = line[start_match.end()-1:]  # Keep the space/end

            # Strip all CTRL+ from the rest
            rest = re.sub(r'CTRL\+([^\s])', r'\1', rest, flags=re.IGNORECASE)

            # Also handle standalone CTRL+ (no char after)
            rest = re.sub(r'CTRL\+(?=\s|$)', '', rest, flags=re.IGNORECASE)

            # Remove standalone CTRL word
            rest = re.sub(r'\bCTRL\b(?!\+)', '', rest, flags=re.IGNORECASE)

            return preserved_start + rest

        # Process line by line
        lines = text.split('\n')
        filtered_lines = [filter_line(line) for line in lines]
        text = '\n'.join(filtered_lines)

        # Clean up any double/multiple spaces
        text = re.sub(r'  +', ' ', text)

        # Clean up space before newline
        text = re.sub(r' +\n', '\n', text)

        # Clean up lines that are now empty or just whitespace
        text = re.sub(r'\n\s*\n', '\n', text)

        return text.strip() if text.strip() else text

    def _refilter_logs(self):
        """Re-apply all filters including CTRL bug filter."""
        self._apply_filter()

    def _on_ctrl_filter_change(self):
        """Handle CTRL bug filter toggle change - update both logs and DuckyScript."""
        # Re-process all logs through the analyzer with current filter state
        self._reprocess_analyzer()
        self._apply_filter()
        if self.redteam_mode.get():
            self._refresh_ducky()

    def _reprocess_analyzer(self):
        """Re-process all stored logs through the analyzer with current filter settings."""
        self.analyzer.reset()
        for msg, color, ts in self.all_logs:
            # Apply CTRL bug filter based on current toggle state
            filtered_msg = self._filter_ctrl_bug_text(msg)
            # Only process lines that look like keystroke data
            if "HID" in msg.upper() or "GUI+" in msg or "ALT+" in msg or "CTRL+" in msg or filtered_msg.strip():
                self.analyzer.add_line(filtered_msg)
        self._update_payload_display()

    def _log(self, msg, color=None, add_ts=True, store=True):
        if store:
            self.all_logs.append((msg, color, add_ts))

        if not self._matches_filter(msg):
            return

        # Apply CTRL bug filter for display
        display_msg = self._filter_ctrl_bug_text(msg)

        self.log_text.configure(state="normal")
        if add_ts and self.show_timestamps.get():
            ts = datetime.now().strftime("[%H:%M:%S] ")
            self.log_text.insert("end", ts, "timestamp")

        if color is None:
            color = get_alert_color(msg)

        tag = None
        for name, c in COLORS.items():
            if c == color:
                tag = name
                break

        if color in [COLORS["danger"], COLORS["warning"]]:
            self.alert_count += 1

        self.log_text.insert("end", display_msg, tag or "fg_normal")
        self.line_count += 1
        self._update_stats()
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        # Also log to RT console if in redteam mode
        if self.redteam_mode.get():
            self._log_rt(display_msg, color)

    def _matches_filter(self, msg):
        fname = self.filter_var.get()
        for name, pat in FILTER_OPTIONS:
            if name == fname:
                if pat and not re.search(pat, msg, re.IGNORECASE):
                    return False
                break
        search = self.search_var.get().strip()
        if search and search.lower() not in msg.lower():
            return False
        return True

    def _apply_filter(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.line_count = 0
        self.alert_count = 0
        for msg, color, ts in self.all_logs:
            if self._matches_filter(msg):
                self._log(msg, color, ts, store=False)

    def _update_stats(self):
        self.stats_label.config(text=f"Lines: {self.line_count} | Alerts: {self.alert_count}")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.rt_log.configure(state="normal")
        self.rt_log.delete("1.0", "end")
        self.rt_log.configure(state="disabled")
        self.all_logs.clear()
        self.line_count = 0
        self.alert_count = 0
        self._update_stats()
        self._reset_analyzer()

    def _save_log(self):
        content = self.log_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("Save", "Nothing to save.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"cerberus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        if filename:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
                f.write("\n\n" + "="*50 + "\nPAYLOAD ANALYSIS\n" + "="*50 + "\n")
                f.write(f"Buffer: {self.analyzer.get_buffer(2000)}\n\n")
                f.write("Patterns:\n")
                for n, s in self.analyzer.detected_patterns:
                    f.write(f"  - {n} ({s})\n")
                f.write("\n\n" + "="*50 + "\nDUCKYSCRIPT EXPORT\n" + "="*50 + "\n")
                f.write(self.analyzer.export_duckyscript())
            self._log(f"Saved to {filename}\n", COLORS["success"])

    def _refresh_ports(self, auto_select=False):
        self.ports_list = list_ports.comports()
        disp = [f"{p.device} - {p.description}" for p in self.ports_list]
        self.port_combo["values"] = disp
        chosen = pick_port(self.ports_list) if auto_select else None
        if chosen:
            self.port_var.set(f"{chosen.device} - {chosen.description}")
            self._set_status("ready", f"Found: {chosen.device}")
        elif disp:
            self.port_var.set(disp[0])
            self._set_status("disconnected", "Select port")
        else:
            self.port_var.set("")
            self._set_status("disconnected", "No ports")

    def _set_status(self, state, text):
        self.status_indicator.set_state(state)
        fg = (COLORS["success"] if state == "connected" else
              COLORS["warning"] if state == "connecting" else
              COLORS["danger"] if state == "error" else COLORS["fg_dim"])
        self.status_label.config(text=text, fg=fg)

    def _toggle_connection(self):
        if self.serial:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        sel = self.port_var.get()
        if not sel:
            messagebox.showerror("Error", "No port selected.")
            return
        device = sel.split(" - ")[0]
        self._set_status("connecting", "Connecting...")
        self.update()
        try:
            self.serial = Serial(device, baudrate=BAUDRATE, timeout=0.2)
        except OSError as e:
            messagebox.showerror("Error", f"Could not open {device}:\n{e}")
            self.serial = None
            self._set_status("error", "Failed")
            return

        self._set_status("connected", f"Connected: {device}")
        self.connect_btn.config(text="Disconnect")
        self.connect_btn.set_style("danger")
        self.stop_event.clear()
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self._log(f"{'='*40}\n  Connected to {device}\n{'='*40}\n\n", COLORS["accent"], False)

    def _disconnect(self):
        self.stop_event.set()
        if self.reader_thread:
            self.reader_thread.join(timeout=1)
            self.reader_thread = None
        if self.serial:
            try: self.serial.close()
            except: pass
            self.serial = None
        self._set_status("disconnected", "Disconnected")
        self.connect_btn.config(text="Connect")
        self.connect_btn.set_style("primary")
        self._log("--- Disconnected ---\n\n", COLORS["fg_dim"])

    def _reader_loop(self):
        reconnect_delay = 1
        while not self.stop_event.is_set():
            try:
                if not self.serial or not self.serial.is_open:
                    raise OSError("Closed")
                line = self.serial.readline()
                if line:
                    try:
                        decoded = line.decode(errors="replace").rstrip('\r\n')
                        if decoded:
                            self.after(0, lambda d=decoded: self._process_line(d))
                    except: pass
                else:
                    time.sleep(0.02)
            except OSError:
                if self.stop_event.is_set():
                    break
                self.after(0, lambda: self._set_status("error", "Lost"))
                if self.auto_reconnect.get() and not self.stop_event.is_set():
                    self.after(0, lambda: self._log("Reconnecting...\n", COLORS["warning"]))
                    if self.serial:
                        try: self.serial.close()
                        except: pass
                        self.serial = None
                    time.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 30)
                    if not self.stop_event.is_set():
                        try:
                            device = self.port_var.get().split(" - ")[0]
                            self.serial = Serial(device, baudrate=BAUDRATE, timeout=0.2)
                            reconnect_delay = 1
                            self.after(0, lambda: self._set_status("connected", "Reconnected"))
                            self.after(0, lambda: self._log("Reconnected!\n", COLORS["success"]))
                        except: pass
                else:
                    self.after(0, self._disconnect)
                    break

    def _process_line(self, line):
        self._log(line + "\n")
        self._check_patterns(line)

    def _on_close(self):
        self._disconnect()
        self.destroy()


def main():
    app = CerberusApp()
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("cerberus.companion")
    except: pass
    app.mainloop()


if __name__ == "__main__":
    main()
