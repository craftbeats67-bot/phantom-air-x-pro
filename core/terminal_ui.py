"""Terminal UI (Rich): branding, logo, menus and helpers shared by every module."""
import os, time
from contextlib import contextmanager
from rich.color import Color
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from core import config

console = Console(theme=Theme({"g": "bold #39ff14", "c": "bold #00e5ff", "p": "bold #b46bff", "r": "bold #ff3b30",
                               "y": "bold #ffd60a", "w": "white", "d": "grey50"}))
SEV = {"CRITICAL": "r", "HIGH": "r", "MEDIUM": "y", "LOW": "c", "OK": "g", "INFO": "w"}
Live = Live

MENU = [("01", "Wireless Interface Manager"), ("02", "Wi-Fi Network Scanner"), ("03", "Network Security Analyzer"),
        ("04", "Signal Analyzer"), ("05", "Channel Information"), ("06", "Authorized Device Inventory"),
        ("07", "Router Security Audit"), ("08", "Password Security Analyzer"), ("09", "Network Monitoring"),
        ("10", "Security Report Generator"), ("11", "Settings"), ("12", "About Phantom Team"), ("00", "Exit")]

FONT = {"P": ["####.", "#...#", "####.", "#....", "#...."], "H": ["#...#", "#...#", "#####", "#...#", "#...#"],
        "A": [".###.", "#...#", "#####", "#...#", "#...#"], "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#"],
        "T": ["#####", "..#..", "..#..", "..#..", "..#.."], "O": [".###.", "#...#", "#...#", "#...#", ".###."],
        "M": ["#...#", "##.##", "#.#.#", "#...#", "#...#"], "I": ["###", ".#.", ".#.", ".#.", "###"],
        "R": ["####.", "#...#", "####.", "#..#.", "#...#"], "X": ["#...#", ".#.#.", "..#..", ".#.#.", "#...#"],
        " ": ["..", "..", "..", "..", ".."]}

def big(word):
    rows = ["", "", "", "", ""]
    for ch in word:
        for i, r in enumerate(FONT.get(ch, FONT[" "])): rows[i] += r.replace("#", "█").replace(".", " ") + " "
    return rows

def clear(): os.system("cls" if os.name == "nt" else "clear")

def logo(width=36):
    """Render the original logo with half-block characters (no distortion, square aspect). None if Pillow is missing."""
    try:
        from PIL import Image
        im = Image.open(config.LOGO).convert("RGB").resize((width, width), Image.LANCZOS)
    except Exception:
        return None
    px, t = im.load(), Text(no_wrap=True)
    for y in range(0, width - 1, 2):
        for x in range(width):
            t.append("▀", style=Style(color=Color.from_rgb(*px[x, y]), bgcolor=Color.from_rgb(*px[x, y + 1])))
        t.append("\n")
    return t

def banner():
    if console.width >= 62:
        for line in big("PHANTOM"): console.print(line, style="c", justify="center")
        for line in big("AIR X PRO"): console.print(line, style="g", justify="center")
    else:
        console.print("PHANTOM AIR X PRO", style="g", justify="center")
    console.print("ADVANCED WI-FI SECURITY SUITE", style="p", justify="center")
    console.print("PHANTOM TEAM  ·  BY KRRISH  ·  INSTAGRAM: @mahisec_13", style="c", justify="center")

def menu_table():
    t = Table(show_header=False, box=None, padding=(0, 1))
    for n, label in MENU:
        t.add_row(Text(f"[{n}]", style="g" if n != "00" else "r"), Text(label, style="w" if n != "00" else "r"))
    return Panel(t, title="[p]MAIN MENU[/p]", border_style="p", expand=False)

def dashboard():
    clear(); banner(); console.print()
    lg = logo(24) if config.get("show_logo") else None
    if lg is not None and console.width >= 90: console.print(Columns([menu_table(), lg], padding=(0, 4)), justify="center")
    else:
        if lg is not None and console.width >= 60: console.print(lg, justify="center")
        console.print(menu_table(), justify="center")

def startup(checks):
    """Startup screen: logo, version and a progress bar driven by the real system checks."""
    clear()
    lg = logo(40) if config.get("show_logo") else None
    if lg is not None: console.print(lg, justify="center")
    banner(); console.print("VERSION 1.0 PRO  ·  DEVELOPED BY KRRISH", style="w", justify="center"); console.print()
    results = []
    with Progress(SpinnerColumn(style="g"), TextColumn("[c]{task.description}"), BarColumn(complete_style="#39ff14"), console=console) as p:
        task = p.add_task("Checking system", total=len(checks))
        for name, fn in checks:
            p.update(task, description=f"Checking {name}"); results.append((name, fn())); time.sleep(0.12); p.advance(task)
    return results

# ---- messages ----
def ok(m): console.print(f"[g][+][/g] {m}")
def warn(m): console.print(f"[y][!][/y] {m}")
def err(m): console.print(f"[r][x][/r] {m}")
def info(m): console.print(f"[c][*][/c] {m}")
def header(title): console.print(); console.rule(f"[p]{title}[/p]", style="p")
def pause(): console.input("\n[d]Press Enter to continue...[/d]")
def prompt(text): return console.input(f"[g]phantom-air >[/g] {text} ").strip()

def confirm(text):
    return console.input(f"[y][?][/y] {text} [d](yes/no)[/d] ").strip().lower() in ("y", "yes")

def sev(s): return Text(s, style=SEV.get(s, "w"))

def table(title, columns, rows):
    t = Table(title=title, title_style="c", header_style="g", border_style="p")
    for c in columns: t.add_column(c)
    for r in rows: t.add_row(*[x if isinstance(x, Text) else str(x) for x in r])
    console.print(t)

@contextmanager
def spinner(msg):
    with console.status(f"[c]{msg}[/c]", spinner="dots"): yield

def about():
    header("ABOUT PHANTOM TEAM")
    lg = logo(30) if config.get("show_logo") else None
    if lg is not None: console.print(lg, justify="center")
    console.print("PHANTOM AIR X PRO - Advanced Wi-Fi Security Suite v1.0 PRO", style="g", justify="center")
    console.print("POWERED BY PHANTOM TEAM · DEVELOPED BY KRRISH · INSTAGRAM: @mahisec_13", style="c", justify="center")
    warn("For authorized defensive auditing only: your own networks and lab environments.")
    info("No cracking, deauthentication, Evil Twin, WPS attacks or handshake capture are implemented.")
