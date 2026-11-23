"""Platform detection and tool availability. Nothing is assumed: every tool is looked up before use."""
import os, platform, shutil, subprocess, sys

def platform_name():
    if os.environ.get("PREFIX", "").startswith("/data/data/com.termux"): return "termux"
    try: txt = open("/etc/os-release").read().lower()
    except OSError: txt = ""
    for k in ("kali", "parrot"):
        if k in txt: return k
    return platform.system().lower() or "unknown"

def have(cmd): return shutil.which(cmd) is not None
def is_root(): return hasattr(os, "geteuid") and os.geteuid() == 0
def python_ok(): return sys.version_info >= (3, 11)

TOOLS = [("iw", "interface capabilities and scans (scan needs root)"), ("nmcli", "Wi-Fi scanning without root"),
         ("ip", "addresses and routes"), ("nmap", "LAN inventory"), ("arp-scan", "LAN inventory (root)"),
         ("termux-wifi-scaninfo", "Wi-Fi scan on Android (Termux:API app + package)")]

def check_all(): return [(n, have(n), why) for n, why in TOOLS]

def run(cmd, timeout=20):
    """Run a command safely (no shell). Returns (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError: return 127, "", f"{cmd[0]}: not installed"
    except subprocess.TimeoutExpired: return 124, "", f"{cmd[0]}: timed out"
    except OSError as e: return 1, "", str(e)
