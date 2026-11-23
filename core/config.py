"""Paths, persistent settings and the in-memory session store used by the report generator."""
import json, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS, LOGS, ASSETS = (os.path.join(ROOT, d) for d in ("reports", "logs", "assets"))
LOGO = os.path.join(ASSETS, "phantom_team_logo.png")
SETTINGS = os.path.join(ROOT, "settings.json")
DEFAULTS = {"backend": "auto", "signal_interval": 2, "show_logo": True, "terms_accepted": False}
SESSION = {}          # scan, analysis, inventory, router, signal ... (never contains passwords)

def load():
    try: data = json.load(open(SETTINGS))
    except (OSError, ValueError): data = {}
    return {**DEFAULTS, **data}

def save(cfg):
    with open(SETTINGS, "w") as f: json.dump(cfg, f, indent=2)

def get(key): return load().get(key, DEFAULTS.get(key))
def set_value(key, value):
    cfg = load(); cfg[key] = value; save(cfg)
