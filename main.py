#!/usr/bin/env python3
"""PHANTOM AIR X PRO - Advanced Wi-Fi Security Suite. PHANTOM TEAM - BY KRRISH - Instagram @mahisec_13"""
import importlib, importlib.util, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from core import config, logger, system_check as sc, terminal_ui as ui
except ImportError as e:
    sys.exit(f"Missing dependency: {e}. Run ./install.sh or: pip install -r requirements.txt")

ROUTES = {"01": "interface_manager", "02": "wifi_scanner", "03": "network_analyzer", "04": "signal_analyzer", "05": "channel_analyzer",
          "06": "device_inventory", "07": "router_audit", "08": "password_analyzer", "09": "network_monitor", "10": "report_generator"}

def terms():
    if config.get("terms_accepted"): return True
    ui.warn("PHANTOM AIR X PRO is for authorized defensive auditing of networks you own or have written permission to test.")
    ui.info("It contains no cracking, deauthentication, Evil Twin, WPS-attack or handshake-capture features.")
    if not ui.confirm("I understand and will only audit authorized networks."): return False
    config.set_value("terms_accepted", True); return True

def settings():
    ui.header("11 · SETTINGS"); cfg = config.load()
    ui.table("Current settings", ["Key", "Value"], [[k, v] for k, v in cfg.items() if k != "terms_accepted"])
    ui.info("Safety confirmations before active scans cannot be disabled.")
    k = ui.prompt("Change which setting? (backend/signal_interval/show_logo, Enter to skip):")
    if k == "backend":
        v = ui.prompt("auto / nmcli / iw / termux:").lower()
        if v in ("auto", "nmcli", "iw", "termux"): config.set_value(k, v); ui.ok("Saved.")
        else: ui.err("Invalid value.")
    elif k == "signal_interval":
        v = ui.prompt("Seconds between samples (1-30):")
        if v.isdigit() and 1 <= int(v) <= 30: config.set_value(k, int(v)); ui.ok("Saved.")
        else: ui.err("Enter a number from 1 to 30.")
    elif k == "show_logo":
        config.set_value(k, ui.confirm("Show the logo?")); ui.ok("Saved.")
    elif k: ui.err("Unknown setting.")

def main():
    log = logger.get()
    checks = [("Python 3.11+", sc.python_ok), ("platform", sc.platform_name), ("tools", lambda: [n for n, ok, _ in sc.check_all() if ok]),
              ("logo asset", lambda: os.path.exists(config.LOGO)), ("Pillow (logo rendering)", lambda: importlib.util.find_spec("PIL") is not None)]
    res = dict(ui.startup(checks))
    if not res["Python 3.11+"]: ui.warn("Python 3.11+ is recommended; some features may misbehave on older versions.")
    ui.info(f"Platform: {res['platform']}  ·  tools found: {', '.join(res['tools']) or 'none'}  ·  root: {'yes' if sc.is_root() else 'no'}")
    if not res["Pillow (logo rendering)"]: ui.warn("Pillow is missing, so the logo is not shown. Install it for the full interface.")
    if not terms(): return
    ui.pause()
    while True:
        ui.dashboard()
        c = ui.prompt("Select option:")
        if not c: continue
        c = c.zfill(2)
        if c == "00": ui.console.print("\nPHANTOM AIR X PRO · POWERED BY PHANTOM TEAM · DEVELOPED BY KRRISH · INSTAGRAM: @mahisec_13", style="g"); return
        try:
            if c in ROUTES: importlib.import_module(f"modules.{ROUTES[c]}").run()
            elif c == "11": settings()
            elif c == "12": ui.about()
            else: ui.err("Choose a number from the menu.")
        except KeyboardInterrupt: ui.console.print()
        except Exception as e:
            log.exception("module %s failed", c); ui.err(f"Module error: {e.__class__.__name__}: {e} (details in logs/phantom.log)")
        ui.pause()

if __name__ == "__main__":
    try: main()
    except (KeyboardInterrupt, EOFError): print()
